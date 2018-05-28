module secured.threading;

version(Botan)
{
    import botan.libstate.init;

    shared static this()
    {
        LibraryInitializer.initialize();
    }
    shared static ~this()
    {
        LibraryInitializer.deinitialize();
    }
}
