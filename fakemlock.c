// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <linux/limits.h>

typedef struct {
  uintptr_t start;
  uintptr_t end;
  int prot;
} ProcMapEntry;

// own_filename uses /proc/self/exe to figure out what the name of the
// running executable is. This is needed to make sure that only the
// executable sections of the current binary are remapped, and not
// that of any shared libraries.
static int own_filename(char* result, size_t bufsiz) {
  return readlink("/proc/self/exe", result, bufsiz);
}

// parse_maps_line takes in a file descriptor to /proc/self/maps and
// parses a single line out of it. The result is returned in the
// ProcMapEntry* out struct. Additionally, if the path name of this
// line matched the desired path, matched is set to true.
static int parse_maps_line(FILE* f, const char* desired_path,
                           ProcMapEntry* out, bool* matched) {
  memset(out, '\0', sizeof(*out));
  char perms[5] = "";
  uintptr_t offset;
  char device[6] = "";
  long unsigned int inode = 0;
  char path[PATH_MAX] = "";

  int ret;
  ret = fscanf(f, "%lx-%lx %4c %lx %5c %lx ",
               &out->start, &out->end, perms,
               &offset, device, &inode);

  if (ret > 0 && ret != EOF) {
    if ((ret += fscanf(f, "%s\n", path)) == 0) {
      fscanf(f, "\n");
    }
  }

  for (char* p = perms; *p; p++) {
    switch (*p) {
    case 'r':
      out->prot |= PROT_READ;
      break;
    case 'w':
      out->prot |= PROT_WRITE;
      break;
    case 'x':
      out->prot |= PROT_EXEC;
      break;
    default:
      break;
    }
  }

  *matched = strcmp(desired_path, path) == 0;
  return ret != 0 && ret != EOF;
}

// remap will use the data in the specified ProcMapEntry to break the
// file-backing. This is done by first creating a new anonymous
// mapping, copying the data into it, updating its protection flags to
// match the original mapping, and then finally mremap'ing it into
// place.
static int remap(ProcMapEntry* entry) {
  ssize_t len = entry->end - entry->start;
  void* tmp_addr = mmap((void*)entry->start, len,
                        PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
                        -1, 0);
  if (tmp_addr == MAP_FAILED) {
    return -1;
  }
  memcpy(tmp_addr, (void*)entry->start, len);
  if (mprotect(tmp_addr, len, entry->prot) < 0) {
    return -1;
  }
  if (mremap(tmp_addr, len, len, MREMAP_MAYMOVE | MREMAP_FIXED,
             entry->start) == MAP_FAILED) {
    return -1;
  }
  return 0;
}

// fakemlock breaks the file-backing for an executable. This is
// particularly useful for helping to guarantee OOMs in low-memory
// environments where swap is disabled, but for whatever reason,
// vm.swapiness, memcg memory.swapiness, or mlock are unavailable.
//
// fakemlock() uses mmap, memcpy, mprotect, and mremap to accomplish
// this task. The linux kernel can normally swap any pages that are
// file-backed, even if swap is disabled. However, if the file-backing
// of the executable pages of the process were to be removed (as by
// fakemlock), then the kernel can no longer swap them. This causes
// the OOM killer to operate rather than allow the linux kernel memory
// management subsystem to thrash while trying to swap code pages
// in/out.
int fakemlock(void) {
  int ret = 0;
  char path[PATH_MAX];
  if (own_filename(path, sizeof(path)) < 0) {
    return -1;
  }
  FILE* maps = fopen("/proc/self/maps", "r");
  if (maps == NULL) {
    return -1;
  }
  ProcMapEntry entry;
  bool matched;
  while (parse_maps_line(maps, path, &entry, &matched)) {
    if (matched && entry.prot & PROT_EXEC) {
      if ((ret = remap(&entry)) < 0) {
        goto fail;
      }
    }
  }
 fail:
  fclose(maps);
  return ret;
}
