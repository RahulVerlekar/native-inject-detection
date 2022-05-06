package com.numadic.framework

open class NuSecurityLib {

    fun runInjectionChecks(): Int {
        if (hasInjection() == 1) {
            return 1
        }
        if (detectnew()) {
            return 1
        }
        return 0
    }

    /**
     * A native method that is implemented by the 'framework' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String

    external fun hasInjection(): Int

    external fun detect(): String

    private external fun detectnew(): Boolean

    companion object {
        // Used to load the 'framework' library on application startup.
        init {
            System.loadLibrary("framework")
        }
    }
}