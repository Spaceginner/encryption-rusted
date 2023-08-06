fn main() {
    cc::Build::new()
        .file("src/poly1305-donna/poly1305-donna.c")
        .compile("poly1305");
}
