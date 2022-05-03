package com.numadic.framework

open class NuSecurityLib {

    /**
     * A native method that is implemented by the 'framework' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String

    external fun hasInjection(): Int

    external fun detect(): String

    companion object {
        // Used to load the 'framework' library on application startup.
        init {
            System.loadLibrary("framework")
        }
    }
}