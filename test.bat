:: adb root
adb push main /data/local/tmp
adb shell chmod 777 /data/local/tmp/main
adb shell /data/local/tmp/main