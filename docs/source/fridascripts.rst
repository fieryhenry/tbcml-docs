Frida Scripting
===============


.. warning::
    You should only use frida scripts if you trust the author of the script. 
    Scripts have full access to the game and can do anything the game can do.

Introduction
------------

Frida is a toolkit that allows you to inject JavaScript into the game.
This allows you to hook functions and modify the behaviour of the game.
This is useful to do more advanced things that are not possible with just editing the game files.
Examples of things you can do with Frida are:

- 0 recharge time
- Always max in-battle money
- Get any amount of any item without the ban risk
  
Frida scripts are written in JavaScript.
If you are not familiar with JavaScript, you can find a lot of tutorials online.
The `Mozilla Developer Network <https://developer.mozilla.org/en-US/docs/Web/JavaScript>`_ is a good place to start.

The JavaScript API for Frida is documented here: https://frida.re/docs/javascript-api/

If you want to inject java code into the game, you can use :doc:`Smali Injection <smaliinjection>` instead.

Setup
----------

You will need to have downloaded the frida-gadget binaries for each architecture you want to target.
You can find them `here <https://github.com/frida/frida/releases>`_.

You then need to extract the binaries and place them in the ``LibGadgets`` folder in the ``tbcml`` folder in ``AppData`` or ``Documents`` directory.
The folder structure should look like this:

.. code-block:: none

    tbcml
    └── LibGadgets
        ├── arm64-v8a
        │   └── libfrida-gadget.so
        ├── armeabi-v7a
        │   └── libfrida-gadget.so
        ├── x86
        │   └── libfrida-gadget.so
        └── x86_64
            └── libfrida-gadget.so

Usage
-----

You need to create a script file with the extension ``.js``.

Helper Functions
----------------

The tool provides you with some helper functions that you can access in your script.

.. code-block:: javascript

    function logError(message) {}
    function logWarning(message) {}
    function logInfo(message) {}
    function logVerbose(message) {}
    function logDebug(message) {}
    function log(message, level = "info" /* "error" | "warning" | "info" | "verbose" | "debug" */) {}

    function getBaseAddress() {}
    function readStdString(address) {}
    function writeStdString(address, content) {}

    function getJavaClass(className) {}

The code for the above functions can be found here :doc:`fridahelpers`.

You can read the logs with ``adb logcat -s tbcml``.

Note that if you do not use the ``getBaseAddress()`` function, then all addresses are offset by ``4096`` due to the libgadget injection into the ``libnative-lib.so`` library.

.. toctree:: 
    :maxdepth: 3

    fridahelpers
