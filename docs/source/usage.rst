Usage
=====

.. _installation:

Installation
------------

To use tbcml, first install it using pip:

.. code-block:: console

   (.venv) $ pip install tbcml


.. _first-mod:

First Mod
----------------

.. code-block:: python

   from tbcml.core import (
      CountryCode,
      GameVersion,
      Apk,
      GamePacks,
      Mod,
      ModEdit,
      CatFormType,
      Cat,
      CatForm,
   )

   # Choose the country code
   cc = CountryCode.EN

   # Choose a game version
   gv = GameVersion.from_string("12.3.0")

   # Get the apk
   apk = Apk(gv, cc)
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
      password="test",
   )

   # Define cat information
   cat_id = 0
   cat_form_type = CatFormType.FIRST

   # Create a form
   form = CatForm.create_empty(cat_id, cat_form_type)

   # Set the form's name to "Test Cat"
   form.name = "Test Cat"

   # Create a cat
   cat = Cat.create_empty(cat_id)

   # Set the form
   cat.set_form(cat_form_type, form)

   # Create a mod edit
   mod_edit = ModEdit(["cats", cat_id], cat.to_dict())

   # Add the mod edit to the mod
   mod.add_mod_edit(mod_edit)

   # Add the mod to the game packs
   apk.load_mods([mod], game_packs)

   # open the apk folder in the file explorer (optional)
   apk_folder.open()