#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sha256.h"

#define HASH2_SHIFT_MIN 1
#define HASH2_SHIFT_MAX 32
#define HASH2_COUNT (HASH2_SHIFT_MAX - HASH2_SHIFT_MIN + 1)
#define HASH1_COUNT 1
#define NUM_HASHES (HASH1_COUNT + HASH2_COUNT)

// Node of a binary tree.
typedef struct treenode_s {
    struct treenode_s *left;
    struct treenode_s *right;
    struct treenode_s *parent;
    uint64_t key;
    uint64_t count;
    int tag;
} treenode_t;

typedef void tree_walk_func_t(treenode_t *node, void *arg);

void tree_free(treenode_t *node)
{
    if (!node)
        return;
    tree_free(node->left);
    tree_free(node->right);
    free(node);
}

// Walks the binary tree in key order, calling the callback function for each node.
void tree_walk(treenode_t *node, tree_walk_func_t *callback, void *arg)
{
    if (!node)
        return;
    tree_walk(node->left, callback, arg);
    callback(node, arg);
    tree_walk(node->right, callback, arg);
}

void tree_check(treenode_t *node)
{
    if (!node)
        return;
    if (node->left) {
        assert(node->left->parent == node);
        assert(node->left->key < node->key);
        assert(node->tag <= node->left->tag);
        tree_check(node->left);
    }
    if (node->right) {
        assert(node->right->parent == node);
        assert(node->right->key > node->key);
        assert(node->tag <= node->right->tag);
        tree_check(node->right);
    }
}

void tree_rebalance(treenode_t *node)
{
    while (node) {
        treenode_t *parent = node->parent;
        if (!parent)
            return;
        treenode_t *ancestor = parent->parent;
        int ancestor_to_left = ancestor && ancestor->left == parent;
        int ancestor_to_right = ancestor && ancestor->right == parent;
        // The parent tag must be smaller than the children tags.
        if (node->tag >= node->parent->tag)
            return;
        // We need to fix the treap.
        if (parent->left == node) {
            // Rotate right:
            //
            //     ancestor        ancestor
            //        |               |
            //     parent           node
            //      /   \           /   \
            //   node    c   =>    a    parent
            //   /  \                    /  \
            //  a    b                  b    c
            //
            treenode_t *a = node->left;
            treenode_t *b = node->right;
            treenode_t *c = parent->right;
            node->right = parent;
            parent->parent = node;
            parent->left = b;
            if (b)
                b->parent = parent;
        } else if (parent->right == node) {
            // Rotate left:
            //
            //     ancestor          ancestor
            //        |                 |
            //     parent             node
            //      /   \             /   \
            //     a    node   =>  parent  c
            //          /  \        /  \
            //         b    c      a    b
            //
            treenode_t *a = parent->left;
            treenode_t *b = node->left;
            treenode_t *c = node->right;
            node->left = parent;
            parent->parent = node;
            parent->right = b;
            if (b)
                b->parent = parent;
        } else {
            assert(0 && "Unreachable");
        }
        // Fix ancestor link.
        if (ancestor_to_left) {
            ancestor->left = node;
        } else if (ancestor_to_right) {
            ancestor->right = node;
        }
        node->parent = ancestor;
    }
}

typedef struct {
    treenode_t *root;
    uint64_t total_count;
    uint64_t key_count;
} treemap_t;

typedef struct {
    uint64_t key;
    uint64_t count;
} key_count_t;

int compare_key_count(const void *a, const void *b)
{
    const key_count_t *pa = a;
    const key_count_t *pb = b;
    if (pa->key < pb->key)
        return -1;
    if (pa->key > pb->key)
        return 1;
    return 0;
}

void treemap_add(treemap_t *tree, uint64_t value)
{
    tree->total_count++;

    // Find the node or the insertion point in the binary tree.
    treenode_t *pointer = tree->root;
    treenode_t *parent = NULL;
    while (pointer) {
        if (value < pointer->key) {
            parent = pointer;
            pointer = pointer->left;
        } else if (value > pointer->key) {
            parent = pointer;
            pointer = pointer->right;
        } else {
            // Found the node.
            break;
        }
    }
    if (pointer) {
        // We found the exact value in the tree.
        assert(pointer->key == value);
        pointer->count++;
        return;
    }
    
    // We did not find the value, so we must create a new node.
    treenode_t *leaf = calloc(1, sizeof(treenode_t));
    leaf->key = value;
    leaf->count = 1;
    // See https://en.wikipedia.org/wiki/Treap
    leaf->tag = rand();

    if (parent) {
        // We did not find the value in the tree,
        // but we know the insertion point.
        if (leaf->key < parent->key) {
            assert(!parent->left);
            parent->left = leaf;
        } else if (leaf->key > parent->key) {
            assert(!parent->right);
            parent->right = leaf;
        } else {
            assert(0 && "Should be unreachable");
        }
        leaf->parent = parent;
        tree_rebalance(leaf);
        //tree_check(tree->root);
    } else {
        // No parent found means that the tree is empty.
        assert(!tree->root);
        tree->root = leaf;
    }
    tree->key_count++;
}

typedef struct {
    treemap_t hashes[NUM_HASHES];
    sha2_context hash1_state;
    uint64_t hash2_state;
} treehash_t;

treehash_t *treehash_create(void)
{
    treehash_t *treehash = calloc(1, sizeof(treehash_t));
    if (!treehash) {
        fprintf(stderr, "Failed to allocate memory for the treehash\n");
        return NULL;
    }
    sha2_starts(&treehash->hash1_state);
    return treehash;
}

void treehash_free(treehash_t *treehash)
{
    if (!treehash)
        return;
    for (int i = 0; i < NUM_HASHES; i++) {
        tree_free(treehash->hashes[i].root);
    }
    free(treehash);
}

void hash1_update(uint8_t *block, uint32_t size, sha2_context *hash_state)
{
    sha2_update(hash_state, block, size);
}

void hash2_update(uint8_t *block, uint32_t size, uint64_t *hash_state)
{
    uint32_t word = 0;
    while (size >= sizeof(word)) {
        memcpy(&word, block, sizeof(word));
        block += sizeof(word);
        size -= sizeof(word);
        *hash_state += word;
    }
}

void treehash_update(uint8_t *block, size_t size, treehash_t *treehash)
{
    hash1_update(block, size, &treehash->hash1_state);
    hash2_update(block, size, &treehash->hash2_state);
    uint8_t sha2_out[32] = {0};
    sha2_finish(&treehash->hash1_state, sha2_out);
    // The problem does not specify how to truncate SHA-2 output to 64 bits.
    // We use the most significant ones.
    uint64_t hash1_value;
    memcpy(&hash1_value, sha2_out, sizeof(hash1_value));
    treemap_add(&treehash->hashes[0], hash1_value);
    for (int shift_index = HASH2_SHIFT_MIN; shift_index <= HASH2_SHIFT_MAX; shift_index++) {
        uint64_t hash_value = treehash->hash2_state >> shift_index;
        int index = HASH1_COUNT + shift_index - HASH2_SHIFT_MIN;
        treemap_add(&treehash->hashes[index], hash_value);
    }
}

// Reads one block of data.
// Returns 1 if success, 0 if end-of-file, negative error code if failure.
int read_block(uint8_t *buffer, int fd, size_t size)
{
    size_t offset = 0;
    while (size) {
        int count = read(fd, buffer, size);
        if (!count) {
            if (!offset) {
                // Reached end of device without partial block read
                return 0;
            }
            fprintf(stderr, "Device size not a multiple of the specified block size\n");
            return -1;
        } else if (count < 0) {
            fprintf(stderr, "Read failed: %s\n", strerror(errno));
            return -1;
        } else if (count > size) {
            fprintf(stderr, "Read more than the specified size\n");
            return -1;
        } else {
            buffer += count;
            size -= count;
            offset += count;
        }
    }
    return 1;
}

int hash_block_dev(const char *path, uint32_t blk_size, treehash_t *treehash)
{
    fprintf(stderr, "Processing '%s'\n", path);
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Failed to open '%s': %s\n", path, strerror(errno));
        return EACCES;
    }

    uint8_t *buffer = calloc(1, blk_size);
    if (!buffer) {
        fprintf(stderr, "Failed to alloc buffer of size %lu\n", (unsigned long)blk_size);
        close(fd);
        return ENOMEM;
    }

    int rc = 0;
    uint64_t total_blocks = 0;
    while (1) {
        int count = read_block(buffer, fd, blk_size);
        if (count == 0) {
            break;
        } else if (count == 1) {
            treehash_update(buffer, blk_size, treehash);
            total_blocks++;
            printf("\rPath: '%s', block count: %llu", path, total_blocks);
        } else {
            fprintf(stderr, "Failed to read block of '%s'\n", path);
            rc = EIO;
        }
    }

    free(buffer);
    close(fd);
    return rc;
}

#define MAX_COLLISIONS 100
typedef struct {
    int64_t collisions_hist[MAX_COLLISIONS];
} hash_stats_t;

void hash_walk_func(treenode_t *node, void *arg)
{
    hash_stats_t *stats = arg;
    int bucket = node->count;
    if (bucket >= MAX_COLLISIONS) {
        bucket = MAX_COLLISIONS - 1;
    }
    stats->collisions_hist[bucket]++;
}

void print_hash_summary(treemap_t *hashmap)
{
    printf("Blocks hashed, total               : %llu\n", hashmap->total_count);
    printf("Blocks hashed, unique              : %llu\n", hashmap->key_count);
    hash_stats_t *stats = calloc(1, sizeof(hash_stats_t));
    if (!stats) {
        fprintf(stderr, "Failed to allocate memory for histogram\n");
        return;
    }
    // twalk(hashmap->root, hash_walk_func);
    tree_walk(hashmap->root, hash_walk_func, stats);
    for (int bucket = 1; bucket < MAX_COLLISIONS; bucket++) {
        uint64_t collisions = stats->collisions_hist[bucket];
        if (collisions) {
            printf("Blocks hashed, with %3d collisions : %llu\n", bucket, collisions);
        }
    }
    free(stats);
}

void print_summary(treehash_t *treehash)
{
    for (int tree_index = 0; tree_index < NUM_HASHES; tree_index++) {
        printf("\nHash function %d:\n", tree_index);
        print_hash_summary(&treehash->hashes[tree_index]);
    }
}

int main(int argc, char **argv)
{
    argc--, argv++;

    size_t blk_size = 512;

    // Process command-line options.
    while (argc) {
        char *arg = *argv;

        if (strcmp(arg, "--blk_size") == 0) {
            argc--, argv++;
            arg = *argv;
            blk_size = atoi(arg);
            argc--, argv++;
        } else if (strcmp(arg, "--help") == 0) {
            printf("Usage:\n");
            printf("block-hash [--blk_size SIZE] PATH1 [PATH2 ...]\n");
            return 0;
        } else if (strcmp(arg, "--") == 0) {
            argc--, argv++;
            break;
        } else if (strchr(arg, '-') == arg) {
            fprintf(stderr, "Unknown argument: %s\n", arg);
            return 1;
        } else {
            break;
        }
    }

    // Process positional arguments.
    treehash_t *treehash = treehash_create();
    if (!treehash) {
        fprintf(stderr, "Failed to create hash trees\n");
        exit(1);
    }
    while (argc) {
        char *path = *argv;
        argc--, argv++;
        hash_block_dev(path, blk_size, treehash);
    }

    print_summary(treehash);
    treehash_free(treehash);
    return 0;
}
