package com.williballenthin.autopsy.wrim;

/**
 * Counter is a silly class to get around `final` references to variables.
 *   Since we use anonymous classes above to process the keys/values, yet
 *   we want to track the number processed, we use this abomination.
 * 
 * Threadsafe.
 * 
 * package-protected.
 */
class Counter {
    private int c;
    public Counter() {
        c = 0;
    }
    
    public synchronized void increment() {
        c++;
    }
    
    public int getValue() {
        return c;
    }
}
