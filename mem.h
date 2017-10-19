template class Memoize<typename T, std::function generate> {
   bool generated;
   T object;
public:
   Memoize(): generated(false);
   T get() {
      if (!generated)
         object = generate();
      return object;
   }
};
