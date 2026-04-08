__BORA_REGISTER_PLUGIN__(

'themes.plugin',

async function (scope) {

    // =========================
    // SERVICES
    // =========================
    const callbora = await scope.getService('callbora');
    const jquery   = await scope.getService('jquery');
    const uiActions = await scope.getService('ui.actions');

    const $ = jquery;

    // =========================
    // STATE
    // =========================
    const state = {
        mounted: false
    };

    // =========================
    // CORE ACTIONS
    // =========================
    function editThemeItem(btnEl){

        const btn = $(btnEl);

        const id  = btn.data('id');
        const itm = btn.closest('tr').find('input.itemvalue').val();

        if (!id || !itm) return;

        uiActions.withLoading(btnEl, async () => {

            const res = await callbora.post(
                `api/modules/themes/themeitem/${id}/edit`,
                { id, itm }
            );

            if (res.response === "success") {

                alertBora.notify(res.message, 'success', 2);

                // Apply CSS variable live
                document.body.style.setProperty(res.data.item, res.data.value);

                // optional: show success state
                uiActions.loading(btnEl, 'success', { resetDelay: 1200 });

            } else {

                alertBora.notify(res.message, 'error', 20);

                // throw to ensure withLoading still finalizes properly if needed
                throw new Error(res.message);
            }
        })
        .catch((err) => {
            console.error(err);
            alertBora.notify("Failed to save theme item", "error", 10);
        });
    }
    async function exportTheme(btnEl) {

        const id = $(btnEl).data('id') ?? 1;

        alertBora.notify("Exporting theme...", 'success');

        const a = document.createElement('a');
        a.href = `api/modules/themes/theme/${id}/export`;
        a.download = '';
        a.click();

    }

    async function importTheme(btnEl) {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'application/json';

        input.onchange = async (e) => {

            const file = e.target.files[0];
            if (!file) return;

            const themeID = $(btnEl).data('id') ?? 1;
            const overwrite = true; // or toggle UI later

            const formData = new FormData();
            formData.append('file', file);
            formData.append('themeID', themeID);
            formData.append('overwrite', overwrite ? 1 : 0);

            try {

                alertBora.notify("Importing theme...", 'success');

                await fetch(`api/modules/themes/theme/${themeID}/import`, {
                    method: 'POST',
                    body: formData
                });

                alertBora.notify("Theme imported successfully", 'success', 2);

                // 🔥 optionally reload styles
                location.reload();

            } catch (err) {
                console.error(err);
                alertBora.notify("Import failed", 'error');
            }
        };

        input.click();
    }

    async function exportThemeO(btnEl) {

        const id = $(btnEl).data('id') ?? 1;

        alertBora.notify("Exporting theme...", 'success');

        try {

            const res = await callbora.get(
                `api/modules/themes/theme/${id}/export`,
                {},
                {
                    responseType: 'blob' // 🔥 critical
                }
            );

            // Create download
            const blob = new Blob([res], { type: 'application/json' });

            const url = window.URL.createObjectURL(blob);

            const a = document.createElement('a');
            a.href = url;
            a.download = `theme-${id}.json`; // or dynamic from headers

            document.body.appendChild(a);
            a.click();

            // cleanup
            a.remove();
            window.URL.revokeObjectURL(url);

            alertBora.notify("Theme exported", 'success', 2);

        } catch (err) {

            console.error(err);
            alertBora.notify("Export failed", "error");

        }
    }

    function exportTheme1(btnEl) {

        const id = $(btnEl).data('id') ?? 1;

        alertBora.notify("Exporting theme...", 'success');

        const win = window.open(
            `api/modules/themes/theme/${id}/export`,
            "themeDownload",
            "width=10,height=10,left=10000,top=10000"
        );

        if (!win) {
            alertBora.notify("Popup blocked. Please allow popups.", "error");
            return;
        }

        win.addEventListener("beforeunload", () => {
            setTimeout(() => {
                if (!win.closed) win.close();
            }, 50);
        });

        setTimeout(() => {
            if (win && !win.closed) win.close();
        }, 3000);
    }

    // =========================
    // DOM BINDINGS
    // =========================

    function bindUI() {
        uiActions.register('themes.saveItem', editThemeItem);

        uiActions.register('themes.export', exportTheme);
        uiActions.register('theme.import', importTheme);

    }

    function unbindUI() {
        uiActions.unregister('themes.saveItem', editThemeItem);
        uiActions.unregister('themes.export', exportTheme);
        uiActions.unregister('theme.import', importTheme);
    }

    // =========================
    // LIFECYCLE
    // =========================

    function mount() {

        if (state.mounted) return;
        state.mounted = true;
        console.log('[themes.plugin] Mounted');
        bindUI();
    }

    function unmount() {

        if (!state.mounted) return;
        state.mounted = false;

        unbindUI();
    }

    // =========================
    // PUBLIC API
    // =========================

    return {
        mount,
        unmount,

        editThemeItem,
        exportTheme
    };

},

{
    requires: ['callbora', 'jquery'],

    activateOn: (route) => route.startsWith('bo/themes'),

    // priority: 10
}
);