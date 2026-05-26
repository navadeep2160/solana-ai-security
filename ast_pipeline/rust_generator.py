class RustASTGenerator:

    def __init__(self):
        self.allowed_nodes = [
            "fn", "struct", "impl", "pub", "use"
        ]

    def generate(self, structured_ir: dict):
        """
        Converts SAFE IR → Rust code ONLY
        """

        rust_code = []

        for item in structured_ir["items"]:

            if item.get("type") == "function":
                rust_code.append(self._build_function(item))

            elif item.get("type") == "struct":
                rust_code.append(self._build_struct(item))

        return "\n\n".join(rust_code)

    def _build_function(self, item):

        name = item.get("name", "unknown_function")

        rust_code = []
        rust_code.append(f"pub fn {name}() {{")

        for check in item.get("security_checks", []):
            rust_code.append(f"    {check}")

        rust_code.append("}")

        return "\n".join(rust_code)

    def _build_struct(self, item):
        name = item.get("name", "UnknownStruct")

        return f"""
#[derive(Clone)]
pub struct {name} {{
    pub value: u64,
}}
"""