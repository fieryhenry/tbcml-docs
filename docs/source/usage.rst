Usage
=====

.. _installation:

Installation
------------

To use tbcml, first install it using pip:

.. code-block:: console

   (.venv) $ pip install tbcml

Basic Usage
----------------

.. code-block:: python

   from tbcml.core import (
      CountryCode,
      GameVersion,
      Apk,
      GamePacks,
      Mod,
      ModEdit,
   )

   cc = CountryCode.EN

   # Choose a game version
   gv = GameVersion.from_string("12.3.0")

   # Get the apk
   apk = Apk(gv, cc, apk_folder)
   apk.download_apk()
   apk.extract()

   # Download server files data
   apk.download_server_files()
   apk.copy_server_files()

   # Get the game data
   game_packs = GamePacks.from_apk(apk)

   # Create a mod id, or use an existing one
   mod_id = Mod.create_mod_id()

   # Create a mod, not all information is required
   mod = Mod(
      name="Test Mod",
      author="Test Author",
      description="Test Description",
      mod_id=mod_id,
      mod_version="1.0.0",
   )

   # Make a mod edit to edit the basic cat's name to "Test Cat"
   mod_edit = ModEdit(["cats", 0, "forms", 0, "name"], "Test Cat")

   # Add the mod edit to the mod
   mod.add_mod_edit(mod_edit)

   # Load the mod into the game
   apk.load_mods([mod], game_packs)
