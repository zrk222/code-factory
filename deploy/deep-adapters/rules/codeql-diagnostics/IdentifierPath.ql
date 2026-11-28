/**
 * @name Path access with an unchecked remote identifier
 * @description Remote input reaches a path operation without a modeled path barrier.
 * @kind path-problem
 * @id factory/js/identifier-guarded-path
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-022
 */
import javascript
import semmle.javascript.security.dataflow.TaintedPathCustomizations

import semmle.javascript.security.dataflow.TaintedPathQuery
import DataFlow::DeduplicatePathGraph<TaintedPathFlow::PathNode, TaintedPathFlow::PathGraph>

/** A synchronous, single-statement validator that throws on a rejected identifier. */
private predicate rejectsInvalidIdentifier(Function validator) {
  exists(IfStmt check, BlockStmt reject, MethodCallExpr test, RegExpLiteral pattern, Variable binding |
    not validator.isAsyncOrGenerator() and
    validator.getNumParameter() = 1 and
    validator.getBody().(BlockStmt).getNumStmt() = 1 and
    check = validator.getBodyStmt(0) and
    not exists(check.getElse()) and
    reject = check.getThen() and reject.getNumStmt() = 1 and reject.getStmt(0) instanceof ThrowStmt and
    test = check.getCondition().(LogNotExpr).getOperand() and test.getMethodName() = "test" and
    test.getNumArgument() = 1 and
    test.getArgument(0).(VarAccess).getVariable() = validator.getParameter(0).(VarDecl).getVariable() and
    binding = test.getReceiver().(VarAccess).getVariable() and
    not binding.getAnAccess().isLValue() and
    pattern = unique(Expr e | e = binding.getAnAssignedExpr()) and
    pattern.getValue().regexpMatch("/\\^\\[(A-Z|a-z|0-9|_)+-?\\]\\+\\$/")
  )
}

/** Only uses of an unchanged parameter in an immediately following return can be barriers. */
class CheckedIdentifierUse extends TaintedPath::Sanitizer {
  CheckedIdentifierUse() {
    exists(Function helper, Variable param, VarAccess use, DataFlow::CallNode call, Function validator |
      this.asExpr() = use and param = use.getVariable() and
      param = helper.getAParameter().(VarDecl).getVariable() and
      not param.getAnAccess().isLValue() and not param.isCaptured() and
      helper.getBody().(BlockStmt).getNumStmt() = 2 and
      call.asExpr() = helper.getBodyStmt(0).(ExprStmt).getExpr() and
      call.getNumArgument() = 1 and call.getArgument(0).asExpr().(VarAccess).getVariable() = param and
      call.asExpr().(CallExpr).getCallee() instanceof VarAccess and
      validator = unique(Function f | f = call.getACallee()) and not call.isUncertain() and
      rejectsInvalidIdentifier(validator) and
      use.getEnclosingStmt() = helper.getBodyStmt(1).(ReturnStmt)
    )
  }
}

from PathNode source, PathNode sink
where TaintedPathFlow::flowPath(source.getAnOriginalPathNode(), sink.getAnOriginalPathNode())
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(), "remote value"
