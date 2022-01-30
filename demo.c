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

// Sample usage
#include <stdio.h>

#include "fakemlock.h"

#define UNUSED __attribute__((unused))

int main(int argc UNUSED, char* argv[] UNUSED) {
  int ret = fakemlock();
  if (ret < 0) {
    perror("fakemlock");
    return 1;
  }
  fprintf(stderr, "If you are reading this line, fakemlock has successfully run.\n");
  return 0;
}
