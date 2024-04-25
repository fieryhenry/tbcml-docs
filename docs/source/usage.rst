Usage
=====

.. _installation:

Installation
------------

To use tbcml, first install it from source:

.. code-block:: console

   $ git clone https://github.com/fieryhenry/tbcml.git
   $ cd tbcml

   $ pip install -r requirements_scripting.txt
   $ pip install -e .


You don't need to install the scripting requirements if you don't want to use the scripting features.

.. _first-mod:

First Mod
----------------

.. code-block:: python

   import tbcml


   class BasicCustomForm(tbcml.CatForm):
      """For better organization, these classes could be defined in
      another / separate files and then imported.

      See game_data/cat_base/cats.py for documetation of cats
      """

      def __init__(self):
         super().__init__(form_type=tbcml.CatFormType.FIRST, name="Cool Cat")

         # you can either set properties in the constructor as shown above, or
         # like this:

         self.description = ["First line!", "Second Line!", "Third description line!"]
         
         # note that if you use .read() it will overwrite any previously defined
         # values, so you may not be able to put the values in the constructor
         # if you want to use .read()


   class BasicCustomCat(tbcml.Cat):
      def __init__(self):
         super().__init__(cat_id=0)

         first_form = BasicCustomForm()
         self.set_form(first_form)


   loader = tbcml.ModLoader(
      "en", "12.3.0"
   )  # these can be changed for the version you want
   loader.initialize_apk()

   apk = loader.get_apk()

   mod = tbcml.Mod(
      name="Test Mod",
      authors="fieryhenry",  # can be a list of authors e.g ["person 1", "person 2"]
      short_description="Test Description",
   )

   cat = BasicCustomCat()
   mod.add_modification(cat)

   mod.save("test.zip") # save the mod to a zip file (optional)

   apk.set_app_name("The Battle Cats Basic Mod")

   # package name should be different to base game if you want your modded app
   # to not replace the normal app.
   apk.set_package_name("jp.co.ponos.battlecats.basicmod")

   # set open_path to True if you want to open the containg folder of the modded apk
   loader.apply(mod, open_path=False)

   print(apk.final_pkg_path)