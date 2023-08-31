Smali Injection
===============

.. warning::
    You should only use smali injection mods if you trust the author of the mod. 
    It allows the mod to have full access to the game and can do anything the game can do.

Introduction
------------

Smali scripting allows you to inject smali code into the ``onCreate()`` method of the main activity.
This allows you to write your own code that will be executed when the app starts up.
This is useful to do more advanced things that are not possible with just editing the game files.

On game versions 6.10.0 and older you can do lots more because the code is written in java.
On newer versions, the code is written in c++ so you can't do as much.
At the moment you can only inject into the ``onCreate()`` method of the main activity.
In the future, I may add support for injecting into other methods and classes.

If you want to hook functions or inject into native library code, you can use :doc:`Frida Scripting <fridascripts>` instead.

Usage
-----
You need to create a script file that will be injected into the app at the beginning of the ``onCreate()`` function.
This script file will be written in smali. You can find the documentation for the smali language `here <https://source.android.com/docs/core/runtime/dalvik-bytecode>`_.

| You could also compile java code to smali using a tool like `java2smali <https://github.com/izgzhen/java2smali>`_.
| Or you can use the tool by running the following code:

.. code-block:: python

    from tbcml.core import Path, SmaliHandler, config, ConfigKey

    # mod is created here:
    ...

    # example class name: com.tbcml.DataLoad
    # example function signature: Start(Landroid/content/Context;)V

    smali = SmaliHandler.java_to_smali(
        Path("{path to java file}"),
        "{class name}",
        "{smali function signature in class to run}"
    )
    if smali is not None:
        mod.smali.import_smali(smali)

    # allow smali mods to be loaded (only needs to be done once)
    config.set(ConfigKey.ALLOW_SCRIPT_MODS, True)

| If you already have compiled smali code, you can use the following code:

.. code-block:: python

    from tbcml.core import Path, SmaliHandler, config, ConfigKey, Smali

    # mod is created here:
    ...

    smali_data = Path("{path to smali file}").read()
    smali = Smali(smali_data, "package.name.ClassName", "smaliFunctionSignatureToCall")
    mod.smali.add(smali)

    # allow smali mods to be loaded (only needs to be done once)
    config.set(ConfigKey.ALLOW_SCRIPT_MODS, True)
    

Example
-------

Java code: `com.tbcml.DataLoad <https://github.com/fieryhenry/TBCModLoader/blob/master/java/com/tbcml/DataLoad.java>`_

| This code will load a data.zip file from the APK assets folder and extract it to the game data folder on startup.
| Inspiration and some of the code is taken from one of those 999999 catfood APKs

Usage
^^^^^

Create a file called ``data.zip`` and add it to the mod with the following code:

.. code-block:: python

    from tbcml.core import Path

    # mod is created here:
    ...

    data_zip = Path("{path to data.zip}")
    mod.add_apk_file("assets/data.zip", data_zip.read())

Example structure:

.. code-block:: none

    data.zip
    ├── files
    │   ├── 09b1058188348630d98a08e0f731f6bd.dat.alwayscopy                                                                                                                                                                     # .alwayscopy means that even if the file exists, extract it
    │   ├── test.txt$url_aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2ZpZXJ5aGVucnkvdGJjbWwvbWFzdGVyL3NyYy90YmNtbC9maWxlcy92ZXJzaW9uLnR4dD90b2tlbj1HSFNBVDBBQUFBQUFDRERSUVhLVVNVSkVXUElPRzNESlRCMlpFWUhQSFE.alwayscopy         # $url_ means that the file should be downloaded from the base64url encoded url
    ├── shared_prefs
    │   ├── save.xml

| Ending with ``.alwayscopy`` means that the file will always be extracted, even if it already exists.
| This is useful for files that need to be updated e.g event data.

| To download a file from a url, you can use ``$url_`` after the file name.
| The url should be base64url encoded. You can use `this tool <https://www.base64encode.org/>`_ to encode the url. Make sure to check ``Perform URL-safe encoding (uses Base64URL format).`` before encoding.

| You can use ``.alwayscopy`` with ``$url_`` to always download the file, even if it already exists.
| Using this you could create an event data private server mod.

.. note:: 
    | Downloading files is performed on a separate thread so it won't freeze the game.
    | This means that if you are downloading a large file and you need it on startup, you may need to wait a few seconds before it is downloaded and then restart the game. 
