package com.technology.jep.jepria.shared;

import com.technology.jep.jepria.shared.util.DefaultComparator;

import java.util.Comparator;

public class AppCompat {


  public static Comparator<Object> getDefaultComparator() {
    return DefaultComparator.instance;
  }
}
