//===- SGXLogicSanitizer.cpp - logic error detector ----------------------===//
//
// This file is a part of LogicSanitizer, a logic basic correctness
// checker.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/SGXLogicSanitizer.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

using namespace llvm;

#define DEBUG_TYPE "sgx_logic"
#define DEBUG_PASS 0

namespace {

/// Get source location string from an instruction
static std::string __attribute_maybe_unused__ getLocStr(const Instruction *I) {
  if (auto *DI = I->getDebugLoc().get()) {
    std::stringstream MySS;
    MySS << (fs::absolute(fs::path(DI->getDirectory().str()) /
                          DI->getFilename().str())
                 .string())
         << ":" << DI->getLine() << ":" << DI->getColumn();
    return MySS.str();
  }
  return "";
}

/// SGXLogicSanitizer:
class SGXLogicSanitizer {
public:
  bool runOnFunction(Function &F) {
#if (DEBUG_PASS)
    dbgs() << "[^] Running SGXLogicSanitizer Pass on " << F.getName() << "\n";
#endif
    bool Changed = false;
    auto &Context = F.getContext();
    auto *M = F.getParent();

    auto PtrSizeBits = M->getDataLayout().getPointerSizeInBits();
    auto *VoidTy = Type::getVoidTy(Context);
    auto *Int32Ty = Type::getInt32Ty(Context);
    auto *PtrTy = PointerType::getUnqual(Context);
    auto *IntptrTy = Type::getIntNTy(Context, PtrSizeBits);

    // Function signature: void __slsan_mem_access(const void *addr, uptr size, int is_write)
    // Value is read by the runtime at the access address
    auto MemAccessFunc = M->getOrInsertFunction(
        "__slsan_mem_access",
        FunctionType::get(VoidTy, {PtrTy, IntptrTy, Int32Ty}, false));
    // For memcpy/memmove/memset - keep as-is (bulk memory operations)
    auto MemmoveFunc = M->getOrInsertFunction(
        "__slsan_memmove",
        FunctionType::get(PtrTy, {PtrTy, PtrTy, IntptrTy}, false));
    auto MemcpyFunc = M->getOrInsertFunction(
        "__slsan_memcpy",
        FunctionType::get(PtrTy, {PtrTy, PtrTy, IntptrTy}, false));
    auto MemsetFunc = M->getOrInsertFunction(
        "__slsan_memset",
        FunctionType::get(PtrTy, {PtrTy, Int32Ty, IntptrTy}, false));

    SmallVector<LoadInst *, 16> LoadsToInstrument;
    SmallVector<StoreInst *, 16> StoresToInstrument;
    SmallVector<MemIntrinsic *, 16> MemIntrinsicsToInstrument;
    SmallVector<AtomicRMWInst *, 16> AtomicRMWsToInstrument;
    SmallVector<AtomicCmpXchgInst *, 16> AtomicCmpXchgsToInstrument;

    for (auto &BB : F) {
      for (auto &I : BB) {
        if (I.hasMetadata(LLVMContext::MD_nosanitize)) {
          continue;
        }

        if (auto *Load = dyn_cast<LoadInst>(&I)) {
          LoadsToInstrument.push_back(Load);
        } else if (auto *Store = dyn_cast<StoreInst>(&I)) {
          StoresToInstrument.push_back(Store);
        } else if (auto *MI = dyn_cast<MemIntrinsic>(&I)) {
          MemIntrinsicsToInstrument.push_back(MI);
        } else if (auto *RMW = dyn_cast<AtomicRMWInst>(&I)) {
          AtomicRMWsToInstrument.push_back(RMW);
        } else if (auto *XCHG = dyn_cast<AtomicCmpXchgInst>(&I)) {
          AtomicCmpXchgsToInstrument.push_back(XCHG);
        }
      }
    }

    IRBuilder<> IRB(Context);

    // Instrument LOADS: insert call AT the load instruction
    for (auto *Load : LoadsToInstrument) {
      Value *Addr = Load->getPointerOperand();
      Type *ValTy = Load->getType();
      uint64_t Size = M->getDataLayout().getTypeStoreSize(ValTy);

#if (DEBUG_PASS)
      std::stringstream ss;
      ss << "[+] Insert __slsan_mem_load() in " << F.getName().str()
         << "\n[*] < " << getLocStr(Load) << " >\n";
      dbgs() << ss.str();
#endif

      // Insert AT the load instruction
      IRB.SetInsertPoint(Load);
      IRB.CreateCall(MemAccessFunc,
                     {Addr, IRB.getIntN(PtrSizeBits, Size),
                      IRB.getInt32(0)}); // 0 = read
      Changed = true;
    }

    // Instrument STORES: insert call AFTER the store (value is still available)
    for (auto *Store : StoresToInstrument) {
      Value *Addr = Store->getPointerOperand();
      Value *StoredVal = Store->getValueOperand();
      uint64_t Size = M->getDataLayout().getTypeStoreSize(StoredVal->getType());

#if (DEBUG_PASS)
      std::stringstream ss;
      ss << "[+] Insert __slsan_mem_store() in " << F.getName().str()
         << "\n[*] < " << getLocStr(Store) << " >\n";
      dbgs() << ss.str();
#endif

      // Insert AFTER the store instruction
      BasicBlock *BB = Store->getParent();
      Instruction *InsertBefore = Store->getNextNode();
      if (!InsertBefore) {
        InsertBefore = BB->getTerminator();
      }
      IRB.SetInsertPoint(InsertBefore);
      IRB.CreateCall(MemAccessFunc,
                     {Addr, IRB.getIntN(PtrSizeBits, Size),
                      IRB.getInt32(1)}); // 1 = write
      Changed = true;
    }

    // For MemIntrinsics (memcpy, memmove, memset) - keep as bulk operations
    // These don't have single values to log, so we just log the operation
    for (auto *MI : MemIntrinsicsToInstrument) {
#if (DEBUG_PASS)
      std::stringstream ss;
      ss << "[+] Replace MemIntrinsic in " << F.getName().str() << "\n[*] < "
         << getLocStr(MI) << " >\n";
      dbgs() << ss.str();
#endif
      IRB.SetInsertPoint(MI);
      if (isa<MemTransferInst>(MI)) {
        IRB.CreateCall(isa<MemMoveInst>(MI) ? MemmoveFunc : MemcpyFunc,
                       {MI->getOperand(0), MI->getOperand(1),
                        IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
      } else if (isa<MemSetInst>(MI)) {
        IRB.CreateCall(
            MemsetFunc,
            {MI->getOperand(0),
             IRB.CreateIntCast(MI->getOperand(1), IRB.getInt32Ty(), false),
             IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
      } else {
        llvm_unreachable("Undefined behavior");
      }
      MI->eraseFromParent();
      Changed = true;
    }

    // For atomic RMW - log the value being written
    for (auto *RMW : AtomicRMWsToInstrument) {
      Value *Addr = RMW->getPointerOperand();
      Value *Val = RMW->getValOperand();
      uint64_t Size = M->getDataLayout().getTypeStoreSize(Val->getType());

      BasicBlock *BB = RMW->getParent();
      Instruction *InsertBefore = RMW->getNextNode();
      if (!InsertBefore) {
        InsertBefore = BB->getTerminator();
      }
      IRB.SetInsertPoint(InsertBefore);
      IRB.CreateCall(MemAccessFunc,
                     {Addr, IRB.getIntN(PtrSizeBits, Size),
                      IRB.getInt32(1)}); // 1 = write
      Changed = true;
    }

    // For atomic cmpxchg - log the new value
    for (auto *XCHG : AtomicCmpXchgsToInstrument) {
      Value *Addr = XCHG->getPointerOperand();
      Value *NewVal = XCHG->getNewValOperand();
      uint64_t Size = M->getDataLayout().getTypeStoreSize(NewVal->getType());

      BasicBlock *BB = XCHG->getParent();
      Instruction *InsertBefore = XCHG->getNextNode();
      if (!InsertBefore) {
        InsertBefore = BB->getTerminator();
      }
      IRB.SetInsertPoint(InsertBefore);
      IRB.CreateCall(MemAccessFunc,
                     {Addr, IRB.getIntN(PtrSizeBits, Size),
                      IRB.getInt32(1)}); // 1 = write
      Changed = true;
    }

    return Changed;
  }
};

} // end anonymous namespace

PreservedAnalyses SGXLogicSanitizerPass::run(Module &M,
                                             ModuleAnalysisManager &) {
  bool Changed = false;
  auto Slsan = SGXLogicSanitizer();
  for (Function &F : M) {
    if (not F.isDeclaration()) {
      if (Slsan.runOnFunction(F)) {
        Changed = true;
      }
    }
  }
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
