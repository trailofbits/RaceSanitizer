/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define DEBUG_TYPE "RaceSanitizer"

#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/CallSite.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>

#include <string>
#include <sstream>
#include <iostream>
#include <set>
#include <vector>

using namespace llvm;

namespace rsan {

struct AllocInfo {
  const char *name;
  unsigned num_args;
  unsigned size_arg;
  int mult_arg;
};

struct AllocLoc {
  CallInst *C;
  const AllocInfo *A;
};

typedef Function *FuncSet[32];

// Various allocator functions. Not using the stuff in `MemoryBuiltins.h/cpp`
// as they don't cover as many allocators, and their ability to get the size
// of an allocation is screwed up on higher optimization levels.
//
// Note: we handle `posix_memalign` by replacing it with
//       `__rsan_posix_memalign`.
static const AllocInfo gAllocators[] = {
  {"_Znwm", 1, 0, -1},
  {"_ZnwmRKSt9nothrow_t", 2, 0, -1},
  {"_Znam", 1, 0, -1},
  {"_ZnamRKSt9nothrow_t", 2, 0, -1},
  {"_ZnwmPv", 2, 0, -1},
  {"_ZnwmPvRKSt9nothrow_t", 3, 0, -1},
  {"_ZnamPv", 2, 0, -1},
  {"_ZnamPvRKSt9nothrow_t", 3, 0, -1},

  {"malloc", 1, 0, -1},
  {"valloc", 1, 0, -1},
  {"pvalloc", 1, 0, -1},
  {"memalign", 2, 1, -1},
  {"aligned_alloc", 2, 1, -1},

  {"calloc", 2, 0, 1},
  {"realloc", 2, 1, -1},
  {"strndup", 2, 1, -1},
  {"reallocf", 2, 1, -1},

  {"mmap", 6, 1, -1},
  {"mremap", 4, 2, -1},
  {"mremap", 5, 2, -1},
};

class RaceSanitizer : public ModulePass {
 public:
  RaceSanitizer();

  virtual const char *getPassName() const override {
    return "RaceSanitizerFunctionPass";
  }
  virtual bool runOnModule(Module &M) override;

  static char ID;

 private:
  void runOnFunction(Function &F);
  void runOnLoadStore(Instruction *I, Value *Ptr, Value *Val,
                      FuncSet &PointerChecks);
  void runOnLoadStoreN(Instruction *I, Value *Ptr, Value *N, Function *Func);
  void runOnAlloc(AllocLoc &I);

  Type *IntPtrTy;
  Type *VoidTy;
  std::set<Value *> Locals;
  std::vector<Instruction *> LoadStores;
  std::vector<AllocLoc> Allocs;
  FuncSet ReadFuncs;
  FuncSet WriteFuncs;
  Function *RecordAlloc;
  Function *WriteN;
  Function *ReadN;
  const DataLayout *DL;
  Module *M;
  LLVMContext *C;
};

template <typename T>
static bool IsAtomic(const T *I) {
  return AtomicOrdering::Unordered < I->getOrdering();
}

template <typename T>
static bool IsThreadLocal(const T *I) {
  return SynchronizationScope::SingleThread == I->getSynchScope();
}

// Identify all local variables.
static std::set<Value *> FindLocals(Function &F) {
  std::set<Value *> Locals;
  for (auto MadeProgress = true; MadeProgress; ) {
    MadeProgress = false;
    for (auto &B : F) {
      for (auto &I : B) {
        if (Locals.count(&I)) continue;

        // If this is an alloca, then the returned address is a local variable.
        if (isa<AllocaInst>(I)) {
          MadeProgress = true;
          Locals.insert(&I);

        // If the base address is a local variable, then the derived address is
        // a local variable.
        } else if (auto G = dyn_cast<GetElementPtrInst>(&I)) {
          if (Locals.count(G->getPointerOperand())) {
            MadeProgress = true;
            Locals.insert(&I);
          }

        // If all inputs are local variables, then the output is a local
        // variables.
        } else if (auto PHI = dyn_cast<PHINode>(&I)) {
          auto NumVals = PHI->getNumIncomingValues();
          auto AllValsLocal = true;
          for (auto i = 0U; i < NumVals; ++i) {
            auto val = PHI->getIncomingValue(i);
            if (!Locals.count(val)) {
              AllValsLocal = false;
              break;
            }
          }
          if (AllValsLocal) {
            MadeProgress = true;
            Locals.insert(&I);
          }
        }
      }
    }
  }
  return Locals;
}

// Identify all loads and stores.
static std::vector<Instruction *> FindLoadStores(Function &F) {
  std::vector<Instruction *> LoadStores;
  for (auto &B : F) {
    for (auto &I : B) {
      if (isa<LoadInst>(I) || isa<StoreInst>(I) || isa<MemCpyInst>(I) ||
          isa<MemMoveInst>(I) || isa<MemSetInst>(I)) {
        LoadStores.push_back(&I);
      }
    }
  }
  return LoadStores;
}

// Get the name of a function.
static StringRef GetFunctionName(CallInst *C) {
  CallSite S(C->stripPointerCasts());
  auto F = S.getCalledFunction();
  if (F) return F->getName();
  return "";
}

// Identify all allocation sites.
static std::vector<AllocLoc> FindAllocs(Function &F) {
  std::vector<AllocLoc> Allocs;
  for (auto &B : F) {
    for (auto &I : B) {
      auto C = dyn_cast<CallInst>(&I);
      if (!C) continue;

      auto N = GetFunctionName(C);
      for (auto &A : gAllocators) {
        if (N == A.name && A.num_args == C->getNumArgOperands()) {
          Allocs.push_back({C, &A});
        }
      }
    }
  }
  return Allocs;
}

// Returns the name of the instrumentation function to invoke.
static std::string FuncName(size_t size, bool IsRead) {
  std::stringstream Name;
  Name << "__rsan_";
  if (IsRead) {
    Name << "read_";
  } else {
    Name << "write_";
  }
  Name << size;
  return Name.str();
}

// Creates a function returning void on some arbitrary number of argument
// types.
template <typename... ParamTypes>
static Function *CreateFunc(Module &M, Type *VoidTy, StringRef name,
                            ParamTypes... Params) {
  std::vector<Type *> FuncParamTypes = {Params...};
  auto FuncType = llvm::FunctionType::get(VoidTy, FuncParamTypes, false);
  return dyn_cast<Function>(M.getOrInsertFunction(name, FuncType));
}

RaceSanitizer::RaceSanitizer(void)
    : ModulePass(ID),
      IntPtrTy(nullptr),
      VoidTy(nullptr),
      RecordAlloc(nullptr),
      WriteN(nullptr),
      ReadN(nullptr),
      DL(nullptr),
      M(nullptr),
      C(nullptr) {}

bool RaceSanitizer::runOnModule(Module &M) {
  C = &(M.getContext());
  DL = &(M.getDataLayout());
  IntPtrTy = Type::getIntNTy(*C,  DL->getPointerSizeInBits());
  VoidTy = Type::getVoidTy(*C);

  memset(&ReadFuncs, 0, sizeof ReadFuncs);
  memset(&WriteFuncs, 0, sizeof WriteFuncs);

  // Declare the sized read and write functions.
  for (auto s = 0; s < 32; ++s) {
    auto name = FuncName(s + 1, true);
    ReadFuncs[s] = CreateFunc(M, VoidTy, name, IntPtrTy);
    name = FuncName(s + 1, false);
    WriteFuncs[s] = CreateFunc(M, VoidTy, name, IntPtrTy);
  }

  // Declare the allocation function and the unsized read and write functions.
  RecordAlloc = CreateFunc(M, VoidTy, "__rsan_record_alloc", IntPtrTy, IntPtrTy);
  WriteN = CreateFunc(M, VoidTy, "__rsan_write_n", IntPtrTy, IntPtrTy);
  ReadN = CreateFunc(M, VoidTy, "__rsan_read_n", IntPtrTy, IntPtrTy);

  for (auto &F : M) {
    // Rename `__posix_memalign` so that we can interpose on it. It has a
    // form that makes it unlike other allocators (it takes in a pointer to
    // the allocated address, and updates that pointer).
    if (F.isDeclaration()) {
      if (F.getName() == "posix_memalign") {
        F.setName("__rsan_posix_memalign");
      }

    } else {
      runOnFunction(F);
    }
  }
  return true;
}

void RaceSanitizer::runOnFunction(Function &F) {
  M = F.getParent();
  Locals = FindLocals(F);
  LoadStores = FindLoadStores(F);
  Allocs = FindAllocs(F);

  // Run on all memory instructions.
  for (auto I : LoadStores) {
    if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
      if (IsThreadLocal(LI) || IsAtomic(LI)) continue;
      auto P = LI->getPointerOperand();
      runOnLoadStore(LI, P, LI, ReadFuncs);

    } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
      if (IsThreadLocal(SI) || IsAtomic(SI)) continue;
      auto P = SI->getPointerOperand();
      auto V = SI->getValueOperand();
      runOnLoadStore(SI, P, V, WriteFuncs);

    } else if (MemCpyInst *MC = dyn_cast<MemCpyInst>(I)) {
      runOnLoadStoreN(MC, MC->getRawSource(), MC->getLength(), ReadN);
      runOnLoadStoreN(MC, MC->getRawDest(), MC->getLength(), WriteN);

    } else if (MemMoveInst *MM = dyn_cast<MemMoveInst>(I)) {
      runOnLoadStoreN(MM, MM->getRawSource(), MM->getLength(), ReadN);
      runOnLoadStoreN(MM, MM->getRawDest(), MM->getLength(), WriteN);

    } else if (MemSetInst *MS = dyn_cast<MemSetInst>(I)) {
      runOnLoadStoreN(MS, MS->getRawDest(), MS->getLength(), WriteN);

    } else {
      llvm_unreachable("unknown Instruction type");
    }
  }

  // Run on all allocation functions.
  for (auto &A : Allocs) {
    runOnAlloc(A);
  }
}

// Instrument an individual load/store instruction.
void RaceSanitizer::runOnLoadStore(Instruction *I, Value *Ptr, Value *Val,
                                         FuncSet &PointerChecks) {
  if (Locals.count(Ptr)) return;
  auto P = Ptr->stripPointerCasts();
  if (Locals.count(P)) return;

  auto Size = DL->getTypeStoreSize(Val->getType());
  if (32 < Size || !PointerChecks[Size - 1]) return;

  auto B = I->getParent();
  if (isa<Constant>(*P)) return;
  auto PointerCheck = PointerChecks[Size - 1];
  auto PointerCast = CastInst::CreatePointerCast(P, IntPtrTy);
  std::vector<Value *> PointerCheckArgs = {PointerCast};
  auto CallPointerCheck = CallInst::Create(PointerCheck, PointerCheckArgs);
  B->getInstList().insert(I, dyn_cast<Instruction>(PointerCast));
  B->getInstList().insert(I, CallPointerCheck);
}

// Instrument an arbitrary sized load/store instruction.
void RaceSanitizer::runOnLoadStoreN(Instruction *I, Value *Ptr,
                                          Value *Size, Function *PointerCheck) {
  if (Locals.count(Ptr)) return;
  auto P = Ptr->stripPointerCasts();
  if (Locals.count(P)) return;

  auto B = I->getParent();
  if (isa<Constant>(*Ptr)) return;
  auto PointerCast = CastInst::CreatePointerCast(P, IntPtrTy);

  std::vector<Value *> PointerCheckArgs = {PointerCast, Size};
  auto CallPointerCheck = CallInst::Create(PointerCheck, PointerCheckArgs);

  B->getInstList().insert(I, dyn_cast<Instruction>(PointerCast));
  B->getInstList().insert(I, CallPointerCheck);
}

// Instrument a malloc-like function.
void RaceSanitizer::runOnAlloc(AllocLoc &I) {
  auto C = I.C;
  auto B = C->getParent();
  auto Size = C->getArgOperand(I.A->size_arg);

  if (-1 != I.A->mult_arg) {
    auto Scale = C->getArgOperand(I.A->mult_arg);
    auto Mult = BinaryOperator::CreateNUW(
        Instruction::BinaryOps::Mul, Size, Scale);
    B->getInstList().insert(C, Mult);
    Size = Mult;
  }

  auto SizeCast = CastInst::CreateIntegerCast(Size, IntPtrTy, false);
  B->getInstList().insert(C, SizeCast);

  auto PointerCast = CastInst::CreatePointerCast(C, IntPtrTy);

  std::vector<Value *> RecordAllocArgs = {PointerCast, SizeCast};
  auto CallRecordAlloc = CallInst::Create(RecordAlloc, RecordAllocArgs);

  B->getInstList().insertAfter(C, CallRecordAlloc);
  B->getInstList().insertAfter(C, PointerCast);
}

char RaceSanitizer::ID = 0;

static RegisterPass<RaceSanitizer> X(
    "rsan",
    "Data race detector.",
    false,  // Only looks at CFG.
    false);  // Analysis Pass.

}  // namespace rsan

