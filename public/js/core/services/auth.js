__BORA_REGISTER_SERVICE__(
    'auth',
    function(scope){

        let currentRole = window.APP_CURRENT_ROLE || null;

        function getRole(){
            return currentRole;
        }

        function setRole(role){

            if (!role || role === currentRole) return;

            currentRole = role;

            // Broadcast role change
            scope.emit?.('role.changed', role);
        }

        return {
            getRole,
            setRole
        };
    }
);