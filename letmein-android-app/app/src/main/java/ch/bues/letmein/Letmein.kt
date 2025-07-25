package ch.bues.letmein

object Letmein {
    init {
        System.loadLibrary("letmein_android")
    }
    external fun init(input: String): String
    external fun foo()
}
