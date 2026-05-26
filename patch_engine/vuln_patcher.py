class VulnerabilityPatcher:

    def apply_patches(self, ast_tree):
        """
        Deterministic fixes (NO LLM dependency here)
        """

        patched = []

        for node in ast_tree:

            # Fix: missing signer check
            if node.get("type") == "function":
                node = self._add_signer_check(node)

            # Fix: missing ownership validation
            node = self._add_owner_check(node)

            patched.append(node)

        return patched

    def _add_signer_check(self, node):

        if "security_checks" not in node:
            node["security_checks"] = []

        node["security_checks"].append(
            "require!(signer.is_signer);"
        )

        return node

    def _add_owner_check(self, node):

        if "security_checks" not in node:
            node["security_checks"] = []

        node["security_checks"].append(
            "require!(account.owner == program_id);"
        )

        return node