# gRPC / protobuf
-keep class io.grpc.**             { *; }
-keep class com.google.protobuf.** { *; }
-keep class com.traceguard.agent.proto.** { *; }

# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keep,includedescriptorclasses class com.traceguard.**$$serializer { *; }
-keepclassmembers class com.traceguard.** {
    *** Companion;
}
-keepclasseswithmembers class com.traceguard.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
