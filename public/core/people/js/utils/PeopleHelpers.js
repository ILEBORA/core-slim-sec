class PeopleHelpers {

    getDisplayName(person) {
        if (!person) return '';

        if (person.name) return person.name;

        const parts = [
            person.first_name,
            person.middle_name,
            person.last_name
        ].filter(Boolean);

        return parts.join(' ') || 'Unknown';
    }

    resolveAvatar(person) {
        if (!person) return 'assets/images/icons/noavatar.png';

        // priority: explicit avatar
        if (person.avatar_url) return person.avatar_url;

        // fallback to user avatar
        if (person.user && person.user.avatar_url) {
            return person.user.avatar_url;
        }

        return 'assets/images/icons/noavatar.png';
    }

    isFollowable(person) {
        return !!person && !!person.user_id; // only real users
    }

    isViewOnly(person) {
        return !person.user_id;
    }

    debounce(fn, delay = 300) {
        let t;
        return function (...args) {
            clearTimeout(t);
            t = setTimeout(() => fn.apply(this, args), delay);
        };
    }
}