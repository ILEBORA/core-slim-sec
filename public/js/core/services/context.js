__BORA_REGISTER_SERVICE__(
    'context',
    function(scope){

        let currentFace = localStorage.getItem('app.face') || 'default';

        function get(){
            return currentFace;
        }

        function set(face){

            if (!face || face === currentFace) return;

            currentFace = face;

            // Persist across reload
            localStorage.setItem('app.face', face);

            // Broadcast change
            scope.emit?.('context.changed', face);
        }

        return { get, set };
    }
);