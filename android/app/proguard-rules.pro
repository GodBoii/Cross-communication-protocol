# R8 rules for CCP.
#
# The app uses no reflection-based serialization (org.json is a platform
# API and all JSON is built by hand), so the default optimize rules are
# enough. Keep line numbers so crash reports stay readable.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
