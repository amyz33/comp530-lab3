/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* A (reverse) trie with fine-grained (per node) locks.
 *
 * Hint: We recommend using a hand-over-hand protocol to order your locks,
 * while permitting some concurrency on different subtrees.

 Name: Amy Zhang    PID: 720402321    
 *     Niko Reingold  PID: 720416077
 *     
 *  Date: 12/7/2016
 *
 *    I certify that no unauthorized assistance has been
 *    received or given in the completion of this work. 
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "trie.h"

pthread_cond_t cond;
pthread_mutex_t signal;
pthread_mutex_t rootLock;

extern int separate_delete_thread;

struct trie_node {
    struct trie_node *next;  /* parent list */
    unsigned int strlen; /* Length of the key */
    int32_t ip4_address; /* 4 octets */
    struct trie_node *children; /* Sorted list of children */
    char key[64]; /* Up to 64 chars */
    pthread_mutex_t mutex;
};

static struct trie_node * root = NULL;
static int node_count = 0;
static int max_count = 5;  //Try to stay at no more than 100 nodes

struct trie_node * new_leaf (const char *string, size_t strlen, int32_t ip4_address) {
  struct trie_node *new_node = malloc(sizeof(struct trie_node));
  node_count++;
  if (!new_node) {
    printf ("WARNING: Node memory allocation failed.  Results may be bogus.\n");
    return NULL;
  }
  assert(strlen < 64);
  assert(strlen > 0);
  new_node->next = NULL;
  new_node->strlen = strlen;
  strncpy(new_node->key, string, strlen);
  new_node->key[strlen] = '\0';
  new_node->ip4_address = ip4_address;
  new_node->children = NULL;

  if (pthread_mutex_init(&new_node->mutex, NULL) != 0)
    printf("\n mutex init failed\n");

  return new_node;
}

int compare_keys (const char *string1, int len1, const char *string2, int len2, int *pKeylen) {
  int keylen, offset;
  char scratch[64];
  assert (len1 > 0);
  assert (len2 > 0);
  // Take the max of the two keys, treating the front as if it were
  // filled with spaces, just to ensure a total order on keys.
  if (len1 < len2) {
    keylen = len2;
    offset = keylen - len1;
    memset(scratch, ' ', offset);
    memcpy(&scratch[offset], string1, len1);
    string1 = scratch;
  } else if (len2 < len1) {
    keylen = len1;
    offset = keylen - len2;
    memset(scratch, ' ', offset);
    memcpy(&scratch[offset], string2, len2);
    string2 = scratch;
  } else
    keylen = len1; // == len2

  assert (keylen > 0);
  if (pKeylen)
    *pKeylen = keylen;
  return strncmp(string1, string2, keylen);
}

int compare_keys_substring (const char *string1, int len1, const char *string2, int len2, int *pKeylen) {
  int keylen, offset1, offset2;
  keylen = len1 < len2 ? len1 : len2;
  offset1 = len1 - keylen;
  offset2 = len2 - keylen;
  assert (keylen > 0);
  if (pKeylen)
    *pKeylen = keylen;
  return strncmp(&string1[offset1], &string2[offset2], keylen);
}

void init(int numthreads) {
  /* Your code here */
  if (pthread_cond_init(&cond, NULL) != 0)
    printf("\n cond int failed\n");

    if (pthread_mutex_init(&rootLock, NULL) != 0)
        printf("\n rootLock init failed\n");


  root = NULL;
}

void shutdown_delete_thread() {
  /* Your code here */
  if ( 0 != pthread_cond_signal(&cond))
    printf("failed to signal\n");
  return;
}

/* Recursive helper function */
int _insert (const char *string, size_t strlen, int32_t ip4_address,
             struct trie_node *node, struct trie_node *parent, struct trie_node *left) {

  int cmp, keylen;

  // First things first, check if we are NULL
  assert (node != NULL);
  assert (node->strlen < 64);

  // Take the minimum of the two lengths
  cmp = compare_keys_substring (node->key, node->strlen, string, strlen, &keylen);
  if (cmp == 0) {
    // Yes, either quit, or recur on the children

    // If this key is longer than our search string, we need to insert
    // "above" this node
    if (node->strlen > keylen) {

      struct trie_node *new_node;

      assert(keylen == strlen);
      assert((!parent) || parent->children == node);

      new_node = new_leaf (string, strlen, ip4_address);
      node->strlen -= keylen;
      new_node->children = node;
      new_node->next = node->next;
      node->next = NULL;

      assert ((!parent) || (!left));

      if (parent) {
        parent->children = new_node;
      } else if (left) {
        left->next = new_node;
      } else if ((!parent) || (!left)) {
        root = new_node;
      }

      return 1;

    } else if (strlen > keylen) {

      if (node->children == NULL) {
        // Insert leaf here
        struct trie_node *new_node = new_leaf (string, strlen - keylen, ip4_address);
        node->children = new_node;
        return 1;
      } else {
        // Recur on children list, store "parent" (loosely defined)
        return _insert(string, strlen - keylen, ip4_address,
                       node->children, node, NULL);
      }
    } else {
      assert (strlen == keylen);
      if (node->ip4_address == 0) {
        node->ip4_address = ip4_address;
        return 1;
      } else {
        return 0;
      }
    }

  } else {
    /* Is there any common substring? */
    int i, cmp2, keylen2, overlap = 0;
    for (i = 1; i < keylen; i++) {
      cmp2 = compare_keys_substring (&node->key[i], node->strlen - i,
                                     &string[i], strlen - i, &keylen2);
      assert (keylen2 > 0);
      if (cmp2 == 0) {
        overlap = 1;
        break;
      }
    }

    if (overlap) {
      // Insert a common parent, recur
      int offset = strlen - keylen2;
      struct trie_node *new_node = new_leaf (&string[offset], keylen2, 0);
      assert ((node->strlen - keylen2) > 0);
      node->strlen -= keylen2;
      new_node->children = node;
      new_node->next = node->next;
      node->next = NULL;
      assert ((!parent) || (!left));

      if (node == root) {
        root = new_node;
      } else if (parent) {
        assert(parent->children == node);
        parent->children = new_node;
      } else if (left) {
        left->next = new_node;
      } else if ((!parent) && (!left)) {
        root = new_node;
      }

       int rv = _insert(string, offset, ip4_address, node, new_node, NULL);

      return rv;
    } else {
      cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
      if (cmp < 0) {
        // No, recur right (the node's key is "less" than  the search key)
        if (node->next) {

            int rv = _insert(string, strlen, ip4_address, node->next, NULL, node);

            return rv;
        } else {
          // Insert here
          struct trie_node *new_node = new_leaf (string, strlen, ip4_address);
          node->next = new_node;
          return 1;
        }
      } else {
        // Insert here
        struct trie_node *new_node = new_leaf (string, strlen, ip4_address);
        new_node->next = node;
        if (node == root)
          root = new_node;
        else if (parent && parent->children == node)
          parent->children = new_node;
        else if (left && left->next == node)
          left->next = new_node;
      }
    }
    return 1;
  }
}

int insert (const char *string, size_t strlen, int32_t ip4_address) {
  /* Your code here */

    //add rootLock mutex

  // Skip strings of length 0
  if (strlen == 0) {
    //check if delete_thread needs signal
    if(max_count < node_count) {
      if ( 0 != pthread_cond_signal(&cond))
        printf("failed to signal\n");
    }
    return 0;
  }

  /* Edge case: root is null */
  if (root == NULL) {
    root = new_leaf (string, strlen, ip4_address);
    //check if delete_thread needs signal
    if(max_count < node_count) {
      if ( 0 != pthread_cond_signal(&cond))
        printf("failed to signal\n");
    }
    return 1;
  }

    pthread_mutex_lock(&root->mutex);
  int rv = _insert (string, strlen, ip4_address, root, NULL, NULL);
    pthread_mutex_unlock(&root->mutex);

  //check if delete_thread needs signal
  if(max_count < node_count) {
    if ( 0 != pthread_cond_signal(&cond))
      printf("failed to signal\n");
  }

  return rv;
}

struct trie_node *
_search (struct trie_node *node, const char *string, size_t strlen) {

  int keylen, cmp;

  // First things first, check if we are NULL
  if (node == NULL) {
      pthread_mutex_unlock(&node->mutex);
      return NULL;
  }

  assert(node->strlen < 64);

  // See if this key is a substring of the string passed in
  cmp = compare_keys_substring(node->key, node->strlen, string, strlen, &keylen);
  if (cmp == 0) {
    // Yes, either quit, or recur on the children

    // If this key is longer than our search string, the key isn't here
    if (node->strlen > keylen) {
        pthread_mutex_unlock(&node->mutex);
      return NULL;
    } else if (strlen > keylen) {
      // Recur on children list
       // pthread_mutex_lock(&node->children->mutex);
        if(node->children != NULL){
          printf("locked child\n");
          pthread_mutex_init(&node->children->mutex, NULL);
          pthread_mutex_lock(&node->children->mutex);
          pthread_mutex_unlock(&node->mutex);
          printf("Unlocked node\n");

          return _search(node->children, string, strlen - keylen);
        }
        else{
          pthread_mutex_unlock(&node->mutex);

          return 0;
        }
    } else {
      assert (strlen == keylen);

      return node;
    }

  } else {
    cmp = compare_keys(node->key, node->strlen, string, strlen, &keylen);
    if (cmp < 0) {
      // No, look right (the node's key is "less" than the search key)
    //  print();
      printf("node->next->key: %p\n", node->next->key);
      printf("node->next->mutex: %p\n", &node->next->mutex);

      if(node->next != NULL){
        pthread_mutex_init(&node->next->mutex, NULL);
        pthread_mutex_lock(&node->next->mutex);
        printf("after lock\n");
        pthread_mutex_unlock(&node->mutex);
        printf("after unlock\n");

        return _search(node->next, string, strlen);
      } else{
        pthread_mutex_unlock(&node->mutex);
        return 0;
      }
    } else {
      // Quit early
        pthread_mutex_unlock(&node->mutex);
      return 0;
    }
  }
}

int search  (const char *string, size_t strlen, int32_t *ip4_address) {
  /* Your code here */
  printf("search\n");
//  printf("Before Search Lock\n");
  struct trie_node *found;
printf("search1\n");
  // Skip strings of length 0
  if (strlen == 0) {
//    printf("After Search Unlock\n");
    return 0;
  }
printf("search2\n");
    pthread_mutex_lock(&root->mutex);
    printf("before _search\n");
  found = _search(root, string, strlen);
  printf("search4\n");
  if (found && ip4_address){
    *ip4_address = found->ip4_address;
  }
printf("search5\n");
//  printf("After Search Unlock\n");

    int rv = (found != NULL);
      printf("search6\n");

      if(rv == 1){
    pthread_mutex_unlock(&found->mutex);
      printf("search7\n");
    }
  return rv;
}

/* Recursive helper function.
 * Returns a pointer to the node if found.
 * Stores an optional pointer to the
 * parent, or what should be the parent if not found.
 *
 */
struct trie_node *
_delete (struct trie_node *node, const char *string,
         size_t strlen) {
  int keylen, cmp;

  // First things first, check if we are NULL
  if (node == NULL) return NULL;

  assert(node->strlen < 64);

  // See if this key is a substring of the string passed in
  cmp = compare_keys_substring (node->key, node->strlen, string, strlen, &keylen);
  if (cmp == 0) {
    // Yes, either quit, or recur on the children

    // If this key is longer than our search string, the key isn't here
    if (node->strlen > keylen) {
      printf("node-strlen > keylen\n");
      return NULL;
    } else if (strlen > keylen) {
      struct trie_node *found =  _delete(node->children, string, strlen - keylen);
      if (found) {
        /* If the node doesn't have children, delete it.
         * Otherwise, keep it around to find the kids */
        if (found->children == NULL && found->ip4_address == 0) {
          assert(node->children == found);
          node->children = found->next;
          free(found);
          node_count--;
        }

        /* Delete the root node if we empty the tree */
        if (node == root && node->children == NULL && node->ip4_address == 0) {
          root = node->next;
          free(node);
          node_count--;
        }

        return node; /* Recursively delete needless interior nodes */
      } else
        return NULL;
    } else {
      assert (strlen == keylen);
      /* We found it! Clear the ip4 address and return. */
      if (node->ip4_address) {
        printf("should reach this point in delete\n");
        node->ip4_address = 0;

        /* Delete the root node if we empty the tree */
        if (node == root && node->children == NULL && node->ip4_address == 0) {
          root = node->next;
          free(node);
          node_count--;
          return (struct trie_node *) 0x100100; /* XXX: Don't use this pointer for anything except
                                                           * comparison with NULL, since the memory is freed.
                                                           * Return a "poison" pointer that will probably
                                                           * segfault if used.
                                                           */
        }
        return node;
      } else {
        /* Just an interior node with no value */
        return NULL;
      }
    }

  } else {
    cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
    if (cmp < 0) {
      // No, look right (the node's key is "less" than  the search key)
      struct trie_node *found = _delete(node->next, string, strlen);
      if (found) {
        /* If the node doesn't have children, delete it.
         * Otherwise, keep it around to find the kids */
        if (found->children == NULL && found->ip4_address == 0) {
          printf("node-next: %p\n", node->next);
          printf("found: %p\n", found);
          assert(node->next == found);
          node->next = found->next;
          free(found);
          node_count--;
        }

        return node; /* Recursively delete needless interior nodes */
      }
      return NULL;
    } else {
      // Quit early
      return NULL;
    }
  }
}

int delete  (const char *string, size_t strlen) {
/* Your code here */

printf("strlen: %zd\n", strlen);
// Skip strings of length 0
if (strlen == 0){
return 0;
}

int rv = (NULL != _delete(root, string, strlen));

return rv;
}

/* Find one node to remove from the tree.
 * Use any policy you like to select the node.
 */
int drop_one_node  () {
  // Your code here
  struct trie_node *node = root;          //Start with root
  int foundLeaf = 0;                      //found leaf boolean
  char * concat = (char *) malloc(1024);
  memset(concat, '\0', 1024);
  char * tmp = (char *) malloc(1024);
  memset(tmp, '\0', 1024);
  int concatlen = 0;
  print("Node cound is %d\n", node_count);

  while (foundLeaf == 0) {

    if (node->children == NULL && node->next == NULL) {
      //found leaf
      strncpy(tmp, node->key, node->strlen);
      tmp[node->strlen] = '\0';
      strncat(tmp, concat, concatlen);
      strncpy(concat, tmp, concatlen + node->strlen);
      concatlen = concatlen + node->strlen;
      foundLeaf = 1;
    } else if (node->next != NULL) {
      //switch node to the node right in tree
      node = node->next;
    } else {
      //switch node to the node down in tree
      strncpy(tmp, node->key, node->strlen);
      tmp[node->strlen] = '\0';
      strncat(tmp, concat, concatlen);
      strncpy(concat, tmp, concatlen + node->strlen);
      concatlen = concatlen + node->strlen;
      node = node->children;
    }
  }

  concat[concatlen] = '\0';

  printf("Node key: %s\n", node->key);
  printf("concat: %s\n", concat);
  int result = (NULL != _delete (root, concat, concatlen));
  printf("delete result: %d\n", result);
  printf("tmplength: %ld\n", strlen(tmp));

  free(tmp);
  free(concat);
  return result;

}

/* Check the total node count; see if we have exceeded a the max.
 */
void check_max_nodes  () {

  if (separate_delete_thread) {

    pthread_cond_wait(&cond, &signal);

    while (node_count > max_count) {
      //        printf("Warning: not dropping nodes yet.  Drop one node not implemented\n");
      //        break;
      drop_one_node();
      printf("node_count: %d\n", node_count);
    }
    pthread_mutex_unlock(&signal);
  }
}


void _print (struct trie_node *node) {
  printf ("Node at %p.  Key %.*s, IP %d.  Next %p, Children %p\n",
          node, node->strlen, node->key, node->ip4_address, node->next, node->children);
  if (node->children)
    _print(node->children);
  if (node->next)
    _print(node->next);
}

void print() {
  printf ("Root is at %p\n", root);
  /* Do a simple depth-first search */
  if (root)
    _print(root);
}