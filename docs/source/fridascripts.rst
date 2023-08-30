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

You can download them with the following code:

.. code-block:: python

    from tbcml.core import Apk

    Apk.download_libgadgets()

Usage
-----

| You need to create a script file with the extension ``.js``.
| You can then add the script to your mod with the following code:

.. code-block:: python

    from tbcml.core import Path, FridaScript

    # mod, gv and cc are created here:
    ...

    script_js = Path("script.js")
    id = FridaScript.create_id()
    script = FridaScript("{arcitecture}", cc, gv, script_js.read().to_str(), "{script_name}", id, mod)
    mod.scripts.add_script(script)

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

    function getArcitecture() {}
    function getPackageName() {}
    function getPackageVersion() {}

The code for the above functions can be found here :doc:`fridahelpers`.

You can read the logs with ``adb logcat -s tbcml``.

.. note:: 
    Note that if you do not use the ``getBaseAddress()`` function, then all addresses are offset by ``4096`` due to the libgadget injection into the ``libnative-lib.so`` library.

Examples
--------

Versions > 8.4.0
^^^^^^^^^^^^^^^^

.. code-block:: javascript

    let address = getBaseAddress().add(0x7fb370)

    Interceptor.attach(address, { // uint * ObfuscatedString::get(uint *param_1,byte **param_2)
        onLeave: function (retval) {
            log("ObfuscatedString::get: " + readStdString(retval))
        }
    });

| The above code hooks into the ``ObfuscatedString::get`` function and prints the result of the function call.
| Effectively leaking any secret / important strings in the game.

.. note:: 
    | The above code only works for x86 running version 12.2.0en of the game.
    | You will need to find the correct address for your version of the game and architecture
    | by using a disassembler such as `Ghidra <https://ghidra-sre.org/>`_ or `IDA <https://www.hex-rays.com/products/ida/>`_.
    
    | Make sure you rebase the binary to ``0x0`` before using the address so that the address is the same as the one in the game.

Versions <= 8.4.0 and > 6.10.0
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: javascript

    let asave_sym = "_ZN13MyApplication5asaveERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE" // MyApplication::asave(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>> const&)
    let asave_address = Module.findExportByName("libnative-lib.so", asave_sym)
    Interceptor.attach(asave_address, {
        onEnter: function (args) {
            let gatya_set_sym = "_ZN15GatyaItemHelper3setEii" // GatyaItemHelper::set(int, int)
            let gatya_set_address = Module.findExportByName("libnative-lib.so", gatya_set_sym)
            let gatya_set_func = new NativeFunction(gatya_set_address, 'int', ["int", 'int'])
            gatya_set_func(22, 45000) // 22 is the id for catfood
        }
    });

| The above code hooks into the ``MyApplication::asave`` function and sets the amount of catfood to 45000.
| Whenever the game saves, the amount of catfood will be set to 45000.
| This is useful for getting catfood without the ban risk.

Versions <= 6.10.0
^^^^^^^^^^^^^^^^^^

.. code-block:: javascript

    var MyApplication_init = getJavaClass("jp.co.ponos.battlecats.em");

    MyApplication_init["save"].implementation = function () {
        let GatyaHelper = getJavaClass("jp.co.ponos.battlecats.bv");
        GatyaHelper.a(22, 45000); // GatyaHelper.set(int, int) 22 is the id for catfood
        this["save"]();
    };

| The above code does the same thing as the example for versions <= 8.4.0 and > 6.10.0.

.. toctree:: 
    :maxdepth: 3

    fridahelpers
