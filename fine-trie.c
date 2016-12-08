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
          pthread_mutex_unlock(&parent->mutex);                             //unlock parent node
      } else if (left) {
        left->next = new_node;
          pthread_mutex_unlock(&left->mutex);                               //unlock left node
      } else if ((!parent) || (!left)) {
        root = new_node;
      }

      printf("scenrio 1, insert as parent\n");
      return 1;

    } else if (strlen > keylen) {

      if (node->children == NULL) {
        // Insert leaf here
        struct trie_node *new_node = new_leaf (string, strlen - keylen, ip4_address);
        node->children = new_node;

          if(parent != NULL)                                                //release parent of current node
              pthread_mutex_unlock(&parent->mutex);
          if(left != NULL)                                                  //or left of current node
              pthread_mutex_unlock(&left->mutex);

          pthread_mutex_unlock(&node->mutex);                               //unlock current node

        printf("Scenrio 2, insert as child no children\n");
        return 1;
      } else {
        // Recur on children list, store "parent" (loosely defined)
          pthread_mutex_lock(&node->children->mutex);                       //lock child node

          if(parent != NULL)                                                //release parent of current node
              pthread_mutex_unlock(&parent->mutex);
          if(left != NULL)                                                  //or left of current node
              pthread_mutex_unlock(&left->mutex);

          int rv = _insert(string, strlen - keylen, ip4_address,
                       node->children, node, NULL);
          //Maybe need to do something more here?

          pthread_mutex_unlock(&node->children->mutex);
          
        printf("Scenrio 3, insert as child has children\n");
        return rv;
      }
    } else {
      assert (strlen == keylen);
      if (node->ip4_address == 0) {
        node->ip4_address = ip4_address;

          if(parent != NULL)                                                //release parent of current node
              pthread_mutex_unlock(&parent->mutex);
          if(left != NULL)                                                  //or left of current node
              pthread_mutex_unlock(&left->mutex);

          pthread_mutex_unlock(&node->mutex);                               //unlock current node

        printf("Scenrio 4, insert as current no ip\n");
        return 1;
      } else {
          if(parent != NULL)                                                //release parent of current node
              pthread_mutex_unlock(&parent->mutex);
          if(left != NULL)                                                  //or left of current node
              pthread_mutex_unlock(&left->mutex);

          pthread_mutex_unlock(&node->mutex);                               //unlock current node

          printf("Scenrio 5, insert as current ip\n");
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

        pthread_mutex_lock(&new_node->mutex);                                    //lock new_node

        if(parent != NULL)                                                //release parent of current node
            pthread_mutex_unlock(&parent->mutex);
        if(left != NULL)                                                  //or left of current node
            pthread_mutex_unlock(&left->mutex);

       int rv = _insert(string, offset, ip4_address, node, new_node, NULL);

       printf("Scenrio 6\n");

      return rv;
    } else {
      cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
      if (cmp < 0) {
        // No, recur right (the node's key is "less" than  the search key)
        if (node->next) {

            pthread_mutex_lock(&node->next->mutex);                           //lock next node

            if(parent != NULL)                                                //release parent of current node
                pthread_mutex_unlock(&parent->mutex);
            if(left != NULL)                                                  //or left of current node
                pthread_mutex_unlock(&left->mutex);

            int rv = _insert(string, strlen, ip4_address, node->next, NULL, node);

            printf("Scenrio 7\n");
            return rv;
        } else {
          // Insert here
          struct trie_node *new_node = new_leaf (string, strlen, ip4_address);
          node->next = new_node;

            if(parent != NULL)                                                //release parent of current node
                pthread_mutex_unlock(&parent->mutex);
            if(left != NULL)                                                  //or left of current node
                pthread_mutex_unlock(&left->mutex);

            pthread_mutex_unlock(&node->mutex);                               //unlock current node

            printf("Scenrio 8\n");
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

        printf("Scenrio 9\n");
      }
    }
      if(parent != NULL)                                                //release parent of current node
          pthread_mutex_unlock(&parent->mutex);
      if(left != NULL)                                                  //or left of current node
          pthread_mutex_unlock(&left->mutex);

      pthread_mutex_unlock(&node->mutex);                               //unlock current node

      printf("Scenrio 10\n");
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
      pthread_mutex_unlock(&node->mutex);     //if the node is NULL, unlock the node
      return NULL;
  }

  assert(node->strlen < 64);

  // See if this key is a substring of the string passed in
  cmp = compare_keys_substring(node->key, node->strlen, string, strlen, &keylen);
  if (cmp == 0) {
    // Yes, either quit, or recur on the children

    // If this key is longer than our search string, the key isn't here, so we unlock the node
    if (node->strlen > keylen) {
        pthread_mutex_unlock(&node->mutex);    
      return NULL;
    } else if (strlen > keylen) {
      // Recur on children list
        if(node->children != NULL){   //if the current node has children
            pthread_mutex_init(&node->children->mutex, NULL);   //initialize mutex for current node's child
            pthread_mutex_lock(&node->children->mutex);         //lock current node's child
            pthread_mutex_unlock(&node->mutex);                 //unlock current node

          return _search(node->children, string, strlen - keylen);  //recursively call _search with the current node's child as the new node
        }
        else{                         //if the current node does not have children
          pthread_mutex_unlock(&node->mutex);                   //unlock the current node and return 0, meaning we did not find the node

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

      if(node->next != NULL){                           //if the current node has a next node
        pthread_mutex_init(&node->next->mutex, NULL);   //initialize mutex for the next node
        pthread_mutex_lock(&node->next->mutex);         //lock the next node
        pthread_mutex_unlock(&node->mutex);             //unlock current node

        return _search(node->next, string, strlen);     //recursively call _search on next node
      } else{                                           //if current node does not have next node
        pthread_mutex_unlock(&node->mutex);             //unlock current node and return 0. did not find the node
        return 0;
      }
    } else {                                            
      // Quit early
        pthread_mutex_unlock(&node->mutex);             //unlock current node, return 0. did not find node 
      return 0;
    }
  }
}

int search  (const char *string, size_t strlen, int32_t *ip4_address) {
  /* Your code here */

  struct trie_node *found;

  // Skip strings of length 0
  if (strlen == 0) {
    return 0;
  }

  pthread_mutex_lock(&root->mutex);         //lock the root 
  found = _search(root, string, strlen);    //call _search on root given the string and strlen
  if (found && ip4_address){                //if the node is found and the ip address matches the one given
    *ip4_address = found->ip4_address;      //set found's ip address to the given ip address
  }

  int rv = (found != NULL);                 //check if found is NULL and put integer into rv

  if(rv == 1){                              //if found is null, unlock the node
    pthread_mutex_unlock(&found->mutex);
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

        if(node != root){
        pthread_mutex_unlock(&node->mutex);                     //unlock current node
        }

        printf("delete 1\n");
      return NULL;
    } else if (strlen > keylen) {

        if(node->children != NULL){
          pthread_mutex_lock(&node->children->mutex);             //lock child node before recursing
        }
      struct trie_node *found =  _delete(node->children, string, strlen - keylen);
        if(node->children != NULL){
          pthread_mutex_unlock(&node->children->mutex);             //lock child node before recursing
        }

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
        printf("delete 2\n");
        return node; /* Recursively delete needless interior nodes */
      } else {

          if(node != root){
          pthread_mutex_unlock(&node->mutex);                     //unlock current node
          }

          printf("delete 3\n");
          return NULL;
      }
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

        printf("delete 4\n");
        return node;
      } else {
        /* Just an interior node with no value */

          if(node != root){
          pthread_mutex_unlock(&node->mutex);                     //unlock current node
          }

          printf("delete 5\n");
        return NULL;
      }
    }

  } else {
    cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
    if (cmp < 0) {
      // No, look right (the node's key is "less" than  the search key)

        if(node->next != NULL){
         pthread_mutex_lock(&node->next->mutex);
         pthread_mutex_unlock(&node->mutex);
        }

      struct trie_node *found = _delete(node->next, string, strlen);

        if(node->next != NULL){
        pthread_mutex_unlock(&node->next->mutex);
      }

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
        printf("delete 6\n");
        return node; /* Recursively delete needless interior nodes */
      }
        if(node != root){
        pthread_mutex_unlock(&node->mutex);                     //unlock current node
        }
        printf("delete 7\n");
      return NULL;
    } else {
      // Quit early
        if(node != root){
        pthread_mutex_unlock(&node->mutex);                     //unlock current node
        }
        printf("delete 8\n");
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

pthread_mutex_lock(&root->mutex);               //lock root
printf("after root lock\n");
int rv = (NULL != _delete(root, string, strlen));
if(root != NULL){
  pthread_mutex_unlock(&root->mutex);             //unlock root
}
return rv;
}

/* Find one node to remove from the tree.
 * Use any policy you like to select the node.
 */
int drop_one_node  () {
  // Your code here
  struct trie_node *node = root;          //Start with root
  int foundLeaf = 0;                      //found leaf boolean
  char * concat = (char *) malloc(1024);  //allocated memory for variable that will keep the final key
  memset(concat, '\0', 1024);
  char * tmp = (char *) malloc(1024);     //allocated memory temporary variable 
  memset(tmp, '\0', 1024);
  int concatlen = 0;                      //concatlen is the length of the final key
  print("Node cound is %d\n", node_count);

  while (foundLeaf == 0) {                                        //while leaf is not found

    if (node->children == NULL && node->next == NULL) {           //if the node is a leaf
      //found leaf
      strncpy(tmp, node->key, node->strlen);                      //copy node->key into tmp 
      tmp[node->strlen] = '\0';                                   //made sure the node->strlen character of temp is null 
      strncat(tmp, concat, concatlen);                            //added the node key to the final key
      strncpy(concat, tmp, concatlen + node->strlen);             //copied contents of tmp into concat
      concatlen = concatlen + node->strlen;                       //added strlen of node to concatlen
      foundLeaf = 1;                                              //changed foundLeaf to 1 (we found a leaf!)
    } else if (node->next != NULL) {                              //if the next node (not children) has content
      //switch node to the node right in tree
      node = node->next;                                          //made the current node the next node
    } else {                                                      //if the node has children
      //switch node to the node down in tree
      strncpy(tmp, node->key, node->strlen);                      //same as above strncpy and strncat lines
      tmp[node->strlen] = '\0';
      strncat(tmp, concat, concatlen);
      strncpy(concat, tmp, concatlen + node->strlen);
      concatlen = concatlen + node->strlen;
      node = node->children;                                      //make the child of the current node, the current node 
    }
  }

  concat[concatlen] = '\0';                                       //making sure the last character of concat is null

  printf("Node key: %s\n", node->key);
  printf("concat: %s\n", concat);
    pthread_mutex_lock(&root->mutex);                             //lock root
  int result = (NULL != _delete (root, concat, concatlen));       //call delete and the returned int goes into variable result
  pthread_mutex_unlock(&root->mutex);             //unlock root
  printf("delete result: %d\n", result);

  //free earlier mallocs
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