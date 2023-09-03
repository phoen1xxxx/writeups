## Roppenheimer [medium]
In this task we have a vulnerability in the fire_neutron function.
Source code:
``` 
#define MAX_ATOMS   32
#define MAX_COLLIDE 20
#define NAME_LEN    128

void fire_neutron() {
    unsigned int atom;
    std::cout << "atom> ";
    std::cin >> atom;

    if (atoms.find(atom) == atoms.end()) {
        panic("atom does not exist");
    }

    size_t bucket = atoms.bucket(atom);
    size_t bucket_size = atoms.bucket_size(bucket);

    std::pair<unsigned int, uint64_t> elems[MAX_COLLIDE - 1];
    copy(atoms.begin(bucket), atoms.end(bucket), elems);

    std::cout << "[atoms hit]" << std::endl;
    for (size_t i = 0; i < bucket_size; i++) {
        std::cout << elems->first << std::endl;
    }
}
```
This function gets an atom key from as, find a bucket which contains this element and copy all elements from bucket to stack array. Vulnerability is that we can put up to 32 elements into one bucket, but size of stack array is only 19. This stack oferflow gives us a possibility to overwrite return adress adn 16 bytes after that.
It's not enough to execute full rop chain but we have useful gadget provides us possibility to pivot stack to username buffer.

To put 32 atoms into one bucket into unordered_map we need to find collisions. After some test I explored that to put 32 atoms into one bucket we need to use equals keys
by mod 59. After first added elements there are 13 buckets in the unordered_map. After filling unordered_map at this stage there are 29 buckets. Then there will 59 buckets. While we change our stage there rehashing procedure is executing to change size of our map and position in the map is key mod new_size. So to fill 32 element in one bucket and trigger stack overflow we need to use keys such as 59*i.

After stack overflow we build a rop chain using such techniques as stack pivoting. To jump into libc we use pointer into vtable in libstdc++ and it's offset to libc.

