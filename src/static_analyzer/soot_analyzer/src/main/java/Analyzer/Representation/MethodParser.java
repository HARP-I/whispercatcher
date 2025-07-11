package Analyzer.Representation;

import soot.SootMethod;
import soot.Type;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class MethodParser {

    public static Map<SootMethod, MethodParser> methods = new ConcurrentHashMap<>();
    public static Map<SootMethod, MethodParser> encMethods = new ConcurrentHashMap<>();

    public final SootMethod sootMethod;
    public Set<MethodParser> next = new HashSet<>();
    public Set<MethodParser> pre = new HashSet<>();

    private MethodParser(SootMethod sootMethod) {
        this.sootMethod = sootMethod;
        methods.put(sootMethod, this);
    }

    // for serialization in json file
    @Override
    public String toString() {
        int totalParams = this.sootMethod.getParameterTypes().size();
        List<Type> paramTypes = this.sootMethod.getParameterTypes();
        Type returnType = this.sootMethod.getReturnType();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i< totalParams; i++) {
            sb.append(paramTypes.get(i).toString());
            if (i < totalParams - 1) {
                sb.append(", ");
            }
        }
        return this.sootMethod.getDeclaringClass() + "." + this.sootMethod.getName() + "(" + sb.toString() + "): " + returnType.toString();
    }

    public static MethodParser getMethodParserOf(SootMethod sootMethod) {
        MethodParser method = methods.get(sootMethod);
        if (method == null) {
            method = new MethodParser(sootMethod); // added the method in the map inner
        }
        return method;
    }

    synchronized
    public void setPreNextRelation(MethodParser method) {
        this.next.add(method);
        method.pre.add(this);
    }

    public void markEncMethod() {
        encMethods.put(this.sootMethod, this);
    }
}

