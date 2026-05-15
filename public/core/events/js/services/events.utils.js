__BORA_REGISTER_SERVICE__('events.utils', async function(){

    function normalizeEvent(event = {}){

        return {
            id: event.id || null,
            title: event.title || '',
            slug: event.slug || '',
            status: event.status || 'draft',
            starts_at: event.starts_at || null,
            ends_at: event.ends_at || null,
            location: event.location || '',
            cover_image: event.cover_image || null,
            ...event
        };
    }

    function isUpcoming(event){

        if(!event?.starts_at) return false;

        return new Date(event.starts_at) > new Date();
    }

    function formatDate(date){

        if(!date) return '';

        return new Date(date)
            .toLocaleString();
    }

    return {
        normalizeEvent,
        isUpcoming,
        formatDate
    };
});