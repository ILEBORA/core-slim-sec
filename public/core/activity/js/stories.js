function renderStories(groups) {
    const $c = $('#storiesContainer').empty();

    groups.forEach(group => {
        const first = group[0];
        const viewed = group.every(s => s.viewed);

        $c.append(`
            <div class="story-item ${viewed ? 'seen' : ''}"
                 data-story="${first.id}">
                <div class="story-avatar">
                    <img src="${first.payload.snapshot.thumb}">
                </div>
                <div class="story-label">Story</div>
            </div>
        `);
    });
}

function loadStories() {
    $.getJSON('api/modules/activity/stories/feed', resp => {
        if (resp.ok) {
            renderStories(resp.data);
        }
    });
}

//Realtime
app.when('sse', function (sse) {
    //SSE is ready
    sse.on('stories', function (msg) {
        loadStories();
    });
});