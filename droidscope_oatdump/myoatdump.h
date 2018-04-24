/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* myoatdump.h
  - Function definitions required to be called be code from droidscope
  - Abhisek VB (abhaskar@syr.edu)
  - 24 November 2015

  */


int entry_main(uint32_t base, const char *file_path);
//void *entry_main(void *thread_data);

int art_method_at(uint32_t base, uint32_t offset, char *method_name);

void clear_all_dumpers();

void test();

