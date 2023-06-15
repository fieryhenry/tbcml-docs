Frida Helper Functions
======================

Table of Contents
-----------------

* `Logging Functions <#id1>`_
    * `logError(message) <#function-logError>`_
    * `logWarning(message) <#function-logWarning>`_
    * `logInfo(message) <#function-logInfo>`_
    * `logVerbose(message) <#function-logVerbose>`_
    * `logDebug(message) <#function-logDebug>`_
    * `log(message, level = "info") <#function-log>`_

* `Reading and Writing Memory <#id2>`_
    * `readStdString(address) <#function-readStdString>`_
    * `writeStdString(address, content) <#function-writeStdString>`_
* `Miscellaneous Functions <#id3>`_
    * `getBaseAddress() <#function-getBaseAddress>`_
* `Java Functions <#id4>`_
    * `getJavaClass(className) <#function-getJavaClass>`_

Logging Functions
-----------------

.. js:function:: function logError(message)
    
        Logs a message to the console and to the Android logcat with the level "error".
    
        :param message: The message to log.
        :type message: str

        Source code:

        .. code-block:: javascript

            function logError(message) {
                Java.perform(function () {
                    var Log = Java.use("android.util.Log");
                    Log.e("tbcml", message);
                    console.error(message);
                });
            }

.. js:function:: function logWarning(message)

    Logs a message to the console and to the Android logcat with the level "warning".

    :param message: The message to log.
    :type message: str

    Source code:

    .. code-block:: javascript

        function logWarning(message) {
            Java.perform(function () {
                var Log = Java.use("android.util.Log");
                Log.w("tbcml", message);
                console.warn(message);
            });
        }

.. js:function:: function logInfo(message)

    Logs a message to the console and to the Android logcat with the level "info".

    :param message: The message to log.
    :type message: str

    Source code:

    .. code-block:: javascript

        function logInfo(message) {
            Java.perform(function () {
                var Log = Java.use("android.util.Log");
                Log.i("tbcml", message);
                console.info(message);
            });
        }
    
.. js:function:: function logVerbose(message)

    Logs a message to the console and to the Android logcat with the level "verbose".

    :param message: The message to log.
    :type message: str

    Source code:

    .. code-block:: javascript

        function logVerbose(message) {
            Java.perform(function () {
                var Log = Java.use("android.util.Log");
                Log.v("tbcml", message);
                console.log(message);
            });
        }
    
.. js:function:: function logDebug(message)

    Logs a message to the console and to the Android logcat with the level "debug".

    :param message: The message to log.
    :type message: str

    Source code:

    .. code-block:: javascript

        function logDebug(message) {
            Java.perform(function () {
                var Log = Java.use("android.util.Log");
                Log.d("tbcml", message);
                console.log(message);
            });
        }
    
.. js:function:: function log(message, level = "info")

    Logs a message to the console and to the Android logcat with the specified level.

    :param message: The message to log.
    :type message: str
    :param level: The level to log the message with. Defaults to "info".
    :type level: str

    Source code:

    .. code-block:: javascript

        function log(message, level = "info") {
            switch (level) {
                case "error":
                    logError(message);
                    break;
                case "warning":
                    logWarning(message);
                    break;
                case "info":
                    logInfo(message);
                    break;
                case "verbose":
                    logVerbose(message);
                    break;
                case "debug":
                    logDebug(message);
                    break;
                default:
                    logInfo(message);
                    break;
            }
        }

Reading and Writing Memory
--------------------------

.. js:function:: function readStdString(address)

    Reads a std::string from the specified address.

    :param address: The address to read the std::string from.
    :type address: NativePointer
    :returns: The std::string at the specified address.
    :rtype: str

    Source code:

    .. code-block:: javascript

        function readStdString(address) {
            const isTiny = (address.readU8() & 1) === 0;
            if (isTiny) {
                return address.add(1).readUtf8String();
            }

            return address.add(2 * Process.pointerSize).readPointer().readUtf8String();
        }

.. js:function:: function writeStdString(address, content)

    Writes a std::string to the specified address.

    :param address: The address to write the std::string to.
    :type address: NativePointer
    :param content: The std::string to write.
    :type content: str

    Source code:

    .. code-block:: javascript

        function writeStdString(address, content) {
            const isTiny = (address.readU8() & 1) === 0;
            if (isTiny)
                address.add(1).writeUtf8String(content);
            else
                address.add(2 * Process.pointerSize).readPointer().writeUtf8String(content);
        }

Miscellaneous Functions
-----------------------

.. js:function:: function getBaseAddress()

    Gets the base address of the current module.

    :returns: The base address of the current module.
    :rtype: NativePointer

    Source code:

    .. code-block:: javascript

        function getBaseAddress() {
            return Module.findBaseAddress("libnative-lib.so").add(4096); // offset due to libgadget being added
        }

Java Functions
--------------

.. js:function:: function getJavaClass(className)

    Gets a Java class by name.

    :param className: The name of the class to get.
    :type className: str
    :returns: The Java class.
    :rtype: Java.ClassFactory

    Source code:

    .. code-block:: javascript

        function getJavaClass(className) {
            var classFactory;
            const classLoaders = Java.enumerateClassLoadersSync();
            for (const classLoader in classLoaders) {
                try {
                    classLoaders[classLoader].findClass(className);
                    classFactory = Java.ClassFactory.get(classLoaders[classLoader]);
                    break;
                } catch (e) {
                    continue;
                }
            }
            return classFactory.use(className);
        }
