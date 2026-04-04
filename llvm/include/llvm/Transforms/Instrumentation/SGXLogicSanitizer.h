//===--------- Definition of the SGXLogicSanitizer class ---------*- C++ -*-===//
//
// This file declares the SGXLogicSanitizer class.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_SGXLOGICSANITIZER_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_SGXLOGICSANITIZER_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class Module;

class SGXLogicSanitizerPass : public PassInfoMixin<SGXLogicSanitizerPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }
};

} // namespace llvm

#endif
