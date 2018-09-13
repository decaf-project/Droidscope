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
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_shared/vmi_callback.h"
#include "vmi_c_wrapper.h"
#include "function_map.h"
#include "vmi.h"
#include "art_vmi.h"


#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "mirror/object.h"
#include "base/logging.h"
#include "base/mutex.h"  // For Locks::mutator_lock_.
#include "globals.h"
#include "invoke_type.h"
#include "jni.h"
#include "modifiers.h"
#include "utf.h"
#include "dex_file.h"
#include  <cstddef>

 #define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)

 namespace art {

// TODO: remove dependencies on mirror classes, primarily by moving
// EncodedStaticFieldValueIterator to its own file.
  namespace mirror {
    class ArtField;
    class ArtMethod;
    class ClassLoader;
    class DexCache;
}  // namespace mirror
class ClassLinker;
class MemMap;
class Signature;
template<class T> class Handle;
class StringPiece;
class ZipArchive;
class MemberOffset;



class MyClassDataItemIterator {
public:
  MyClassDataItemIterator(const DexFile& dex_file, const byte* raw_class_data_item, CPUArchState *env, target_ulong cr3)
  : dex_file_(dex_file), pos_(0), ptr_pos_(raw_class_data_item), last_idx_(0) {
    ReadClassDataHeader();
    if (EndOfInstanceFieldsPos() > 0) {
      ReadClassDataField();
    } else if (EndOfVirtualMethodsPos() > 0) {
      ReadClassDataMethod();
    }
  }
  uint32_t NumStaticFields() const {
    return header_.static_fields_size_;
  }
  uint32_t NumInstanceFields() const {
    return header_.instance_fields_size_;
  }
  uint32_t NumDirectMethods() const {
    return header_.direct_methods_size_;
  }
  uint32_t NumVirtualMethods() const {
    return header_.virtual_methods_size_;
  }
  bool HasNextStaticField() const {
    return pos_ < EndOfStaticFieldsPos();
  }
  bool HasNextInstanceField() const {
    return pos_ >= EndOfStaticFieldsPos() && pos_ < EndOfInstanceFieldsPos();
  }
  bool HasNextDirectMethod() const {
    return pos_ >= EndOfInstanceFieldsPos() && pos_ < EndOfDirectMethodsPos();
  }
  bool HasNextVirtualMethod() const {
    return pos_ >= EndOfDirectMethodsPos() && pos_ < EndOfVirtualMethodsPos();
  }
  bool HasNext() const {
    return pos_ < EndOfVirtualMethodsPos();
  }
  inline void Next() {
    pos_++;
    if (pos_ < EndOfStaticFieldsPos()) {
      last_idx_ = GetMemberIndex();
      ReadClassDataField();
    } else if (pos_ == EndOfStaticFieldsPos() && NumInstanceFields() > 0) {
      last_idx_ = 0;  // transition to next array, reset last index
      ReadClassDataField();
    } else if (pos_ < EndOfInstanceFieldsPos()) {
      last_idx_ = GetMemberIndex();
      ReadClassDataField();
    } else if (pos_ == EndOfInstanceFieldsPos() && NumDirectMethods() > 0) {
      last_idx_ = 0;  // transition to next array, reset last index
      ReadClassDataMethod();
    } else if (pos_ < EndOfDirectMethodsPos()) {
      last_idx_ = GetMemberIndex();
      ReadClassDataMethod();
    } else if (pos_ == EndOfDirectMethodsPos() && NumVirtualMethods() > 0) {
      last_idx_ = 0;  // transition to next array, reset last index
      ReadClassDataMethod();
    } else if (pos_ < EndOfVirtualMethodsPos()) {
      last_idx_ = GetMemberIndex();
      ReadClassDataMethod();
    } else {
      DCHECK(!HasNext());
    }
  }
  uint32_t GetMemberIndex() const {
    if (pos_ < EndOfInstanceFieldsPos()) {
      return last_idx_ + field_.field_idx_delta_;
    } else {
      DCHECK_LT(pos_, EndOfVirtualMethodsPos());
      return last_idx_ + method_.method_idx_delta_;
    }
  }
  uint32_t GetRawMemberAccessFlags() const {
    if (pos_ < EndOfInstanceFieldsPos()) {
      return field_.access_flags_;
    } else {
      DCHECK_LT(pos_, EndOfVirtualMethodsPos());
      return method_.access_flags_;
    }
  }
  uint32_t GetFieldAccessFlags() const {
    return GetRawMemberAccessFlags() & kAccValidFieldFlags;
  }
  uint32_t GetMethodAccessFlags() const {
    return GetRawMemberAccessFlags() & kAccValidMethodFlags;
  }
  bool MemberIsNative() const {
    return GetRawMemberAccessFlags() & kAccNative;
  }
  bool MemberIsFinal() const {
    return GetRawMemberAccessFlags() & kAccFinal;
  }
  InvokeType GetMethodInvokeType(const DexFile::ClassDef& class_def) const {
    if (HasNextDirectMethod()) {
      if ((GetRawMemberAccessFlags() & kAccStatic) != 0) {
        return kStatic;
      } else {
        return kDirect;
      }
    } else {
      DCHECK_EQ(GetRawMemberAccessFlags() & kAccStatic, 0U);
      if ((class_def.access_flags_ & kAccInterface) != 0) {
        return kInterface;
      } else if ((GetRawMemberAccessFlags() & kAccConstructor) != 0) {
        return kSuper;
      } else {
        return kVirtual;
      }
    }
  }
  const DexFile::CodeItem* GetMethodCodeItem() const {
    return dex_file_.GetCodeItem(method_.code_off_);
  }
  uint32_t GetMethodCodeItemOffset() const {
    return method_.code_off_;
  }
  const byte* EndDataPointer() const {
    CHECK(!HasNext());
    return ptr_pos_;
  }

private:
  // A dex file's class_data_item is leb128 encoded, this structure holds a decoded form of the
  // header for a class_data_item
  struct ClassDataHeader {
    uint32_t static_fields_size_;  // the number of static fields
    uint32_t instance_fields_size_;  // the number of instance fields
    uint32_t direct_methods_size_;  // the number of direct methods
    uint32_t virtual_methods_size_;  // the number of virtual methods
  } header_;

  // Read and decode header from a class_data_item stream into header
  void ReadClassDataHeader()
  {
    CHECK(ptr_pos_ != NULL);
    header_.static_fields_size_ = DecodeUnsignedLeb128(&ptr_pos_);
    header_.instance_fields_size_ = DecodeUnsignedLeb128(&ptr_pos_);
    header_.direct_methods_size_ = DecodeUnsignedLeb128(&ptr_pos_);
    header_.virtual_methods_size_ = DecodeUnsignedLeb128(&ptr_pos_);
  }

  uint32_t EndOfStaticFieldsPos() const {
    return header_.static_fields_size_;
  }
  uint32_t EndOfInstanceFieldsPos() const {
    return EndOfStaticFieldsPos() + header_.instance_fields_size_;
  }
  uint32_t EndOfDirectMethodsPos() const {
    return EndOfInstanceFieldsPos() + header_.direct_methods_size_;
  }
  uint32_t EndOfVirtualMethodsPos() const {
    return EndOfDirectMethodsPos() + header_.virtual_methods_size_;
  }

  // A decoded version of the field of a class_data_item
  struct ClassDataField {
    uint32_t field_idx_delta_;  // delta of index into the field_ids array for FieldId
    uint32_t access_flags_;  // access flags for the field
    ClassDataField() :  field_idx_delta_(0), access_flags_(0) {}

  private:
    DISALLOW_COPY_AND_ASSIGN(ClassDataField);
  };
  ClassDataField field_;

  // Read and decode a field from a class_data_item stream into field
  void ReadClassDataField()
  {
    field_.field_idx_delta_ = DecodeUnsignedLeb128(&ptr_pos_);
    field_.access_flags_ = DecodeUnsignedLeb128(&ptr_pos_);
    if (last_idx_ != 0 && field_.field_idx_delta_ == 0) {
      LOG(WARNING) << "Duplicate field in " << dex_file_.GetLocation();
    }
  }


  // A decoded version of the method of a class_data_item
  struct ClassDataMethod {
    uint32_t method_idx_delta_;  // delta of index into the method_ids array for MethodId
    uint32_t access_flags_;
    uint32_t code_off_;
    ClassDataMethod() : method_idx_delta_(0), access_flags_(0), code_off_(0) {}

  private:
    DISALLOW_COPY_AND_ASSIGN(ClassDataMethod);
  };
  ClassDataMethod method_;

  // Read and decode a method from a class_data_item stream into method
  void ReadClassDataMethod()
  {
    method_.method_idx_delta_ = DecodeUnsignedLeb128(&ptr_pos_);
    method_.access_flags_ = DecodeUnsignedLeb128(&ptr_pos_);
    method_.code_off_ = DecodeUnsignedLeb128(&ptr_pos_);
    if (last_idx_ != 0 && method_.method_idx_delta_ == 0) {
      LOG(WARNING) << "Duplicate method in " << dex_file_.GetLocation();
    }
  }

  const DexFile& dex_file_;
  size_t pos_;  // integral number of items passed
  const byte* ptr_pos_;  // pointer into stream of class_data_item
  uint32_t last_idx_;  // last read field or method index to apply delta to

  DISALLOW_IMPLICIT_CONSTRUCTORS(MyClassDataItemIterator);
};
}
