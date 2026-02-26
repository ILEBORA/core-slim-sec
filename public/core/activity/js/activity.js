const ActivityFeed = {
    el: '#activityFeed',
    scope: 'home',
    limit: 20,
    since: null,
    loading: false,

    init() {
        const $el = $(this.el);
        if (!$el.length) return;

        this.scope = $el.data('scope') || 'home';

        this.load();

        // realtime hook
        this.bindRealtime();
    },

    load(reset = false) {

        if (this.loading) return;
        this.loading = true;
        $('.timeline-loading').show();

        if (reset) {
            this.since = null;
            $(this.el).empty();
        }

        $.getJSON('api/modules/activity/feed', {
            scope: this.scope,
            since: this.since,
            limit: this.limit
        }).done(resp => {
            if (!resp.ok || !resp.data.length) return;

            if (resp.ok && !resp.data.length && !this.since) {
                $(this.el).html(`
                    <div class="activity-item">
                        <em>No activity yet.</em>
                    </div>
                `);
            }

            resp.data.forEach(item => {
                // this.render(item);
                $(this.el).append(item.html);
                this.since = item.created_at;
            });


        }).always(() => {
            this.loading = false;
            $('.timeline-loading').hide();
        });
    },

    render(item, force = true) {
        const html = `
        <div class="activity-item" data-id="${item.id}">
            ${renderActivityHeader(item)}
            
            <div class="activity-body">
                ${renderMentions(renderHashtags(item.body || ''))}
            </div>

            ${this.renderSnapshot(item)}

            <div class="activity-meta">
                <span class="reactions">
                    ${this.renderReactions(item)}
                </span>
                <span class="comments-count">
                    ${item.comments_count} comments
                </span>
            </div>

            <div class="activity-actions">
                <a href="#" class="act-like" data-reaction="like">
                    ${item.reactions.me === 'like' ? 'Unlike' : 'Like'}
                </a>
                <div class="reaction-picker">
                    <a href="#" class="act-react" data-reaction="like">👍 Like</a>
                    <a href="#" class="act-react" data-reaction="love">❤️ Love</a>
                    <a href="#" class="act-react" data-reaction="haha">😂 Haha</a>
                </div>
                <a href="#" class="act-comment">Comment</a>
            </div>

            <div class="comments"></div>
        </div>
        `;
        if(force){
            $(this.el).append(html);
        }else{
            $(this.el).prepend(html);
        }
    },

    renderSnapshot(item) {
        if (!item.payload || !item.payload.snapshot) return '';

        const snap = item.payload.snapshot;
        return `
            <div class="activity-snapshot">
                <img src="${snap.image}" />
            </div>
        `;
    },

    renderReactions(item) {
        const counts = item.reactions.counts || {};
        return Object.keys(counts)
            .map(k => `${k} (${counts[k]})`)
            .join(' ');
    },

    bindRealtime() {
        FactBus.on('timeline.entry.added', function (event) {
            console.log('Fact:: timeline.entry.added');
            app.SSE.updateWidgetVersions(event);
            timeline.addEntry(event.data);
        });

        FactBus.on('feed.activity.updated', (event) => {
            console.log('Fact:: timeline.entry.updated');
            app.SSE.updateWidgetVersions(event);
            console.log('EVENT Data:: ',event);
            const batch = event.data.events || [];
            console.log('BATCH:: ', batch);
            batch.forEach(ev => {
                const id = ev.payload.id;
                const payload = ev.payload;

                // const $existing = $(
                //     `${this.el} .activity-item[data-id="${id}"]`);
                const $existing = $(
                    `.activity-item[data-id="${id}"]`);

                if ($existing.length) {
                    console.log('test existing element');
                    // $existing.replaceWith(ActivityFeed.renderToNode(payload));
                    $existing.replaceWith(payload.html);
                } else {
                    console.log('test new element');
                    $(this.el).prepend(payload.html);
                }
            });
        });

        FactBus.on('feed.activity.deleted', (event) => {
            console.log('Fact:: feed.activity.deleted');

            app.SSE.updateWidgetVersions(event);

            const id = event.data.id;

            const $existing = $(`.activity-item[data-id="${id}"]`);

            if ($existing.length) {
                $existing.remove();
            }
        });
    },

    bindRealtimeO() {
        // if (!window.BoraRealtime) return;

        // BoraRealtime.on('feed', () => {
        //     this.load(true);
        // });

        // BoraRealtime.onPrefix('activity:', tag => {
        //     const id = tag.split(':')[1];
        //     this.refreshActivity(id);
        // });

        app.when('sse', function (sse) {
            //SSE is ready
            sse.on('timeline.entry.added', function (msg) {
                timeline.addEntry(msg.data);
            });

            sse.on('feed.activity.updated', (msg) => {
                console.log("RAW SSE:", msg);

                // safety checks
                // if (!msg || !msg.data || !Array.isArray(msg.data)) return;

                alertBora.notify("New feed.activity.updated received...");
                const entry = msg.data;                // the item in array
                const batch = entry.events || [];   // events under the widget batch
                console.log("Batch:: ",batch);
                // Loop through each changed activity
                batch.forEach(ev => {
                    const id = ev.id;
                    const payload = ev.payload;

                    // If item exists, replace it.
                    const $existing = $(`#activityFeed .activity-item[data-id="${id}"]`);
                    if ($existing.length) {
                        console.log(`Updating activity ${id}…`);
                        // Play sound
                        // var audio = new Audio('assets/sound/doink.mp3');
                        // audio.play();

                        // $existing.replaceWith(ActivityFeed.renderToNode(payload));
                        $existing.replaceWith(payload.html);
                    } else {
                        // Otherwise prepend new item
                        console.log(`Adding NEW activity ${id}…`);
                        // Play sound
                        // var audio = new Audio('assets/sound/doink.mp3');
                        // audio.play();
                        const $feed = $('#activityFeed'); // direct reference
                        $feed.prepend(ActivityFeed.render(payload, false));
                        console.log($('#activityFeed').children().first());
                    }
                });
            });

        });

    },

    refreshActivity(id) {
        const $item = $(`${this.el} .activity-item[data-id="${id}"]`);
        if (!$item.length) return;

        $.getJSON('api/modules/activity/feed', {
            scope: this.scope,
            limit: 1
        }).done(resp => {
            if (!resp.ok || !resp.data.length) return;

            $item.replaceWith(
                $(this.renderToNode(resp.data[0]))
            );
        });
    },

    renderToNode(item, force) {
        return $(`
            <div class="activity-item" data-id="${item.id}">
                ${this.render(item, force)}
            </div>
        `);
    }
};

function renderMentions(text) {
    return text.replace(
        /@([a-zA-Z0-9_.]{3,30})/g,
        '<a href="portal/person/$1" class="mention">@$1</a>'
    );
}

function renderHashtags(text) {
    return text.replace(
        /#([a-zA-Z0-9_]{2,50})/g,
        '<a href="portal/activity/hashtag/$1" class="hashtag">#$1</a>'
    );
}

function renderActivityHeader(item) {
    const actor = item.actor || {};
    const avatar = actor.avatar || 'assets/images/icons/noavatar.png';
    const name = actor.name || 'Unknown';
    const username = actor.username ? `@${actor.username}` : '';
    const time = item.timeago_format;//timeAgo(item.timeago);

    return `
        <div class="activity-header">
            <img class="activity-avatar" src="${avatar}" alt="">
            <div class="activity-meta">
                <div class="activity-author">
                    <a href="portal/person/${actor.id || actor.id}">
                        ${name}
                    </a>
                    <span class="activity-username">${username}</span>
                </div>
                <div class="activity-time">${time}</div>
            </div>
        </div>
    `;
}

function timeAgo(ts) {
    const now = Date.now() / 1000;  // convert ms → seconds
    const seconds = Math.floor(now - ts);

    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h';
    return Math.floor(seconds / 86400) + 'd';
}


// ------------------------------------------------------------
// Reactions
// ------------------------------------------------------------

$(document).on('click', '.reaction-trigger', function (e) {
    e.preventDefault();
    $(this).closest('.reaction-box').toggleClass('open');
});

$(document).on('click', '.act-react', function () {
    const $btn     = $(this);
    const reaction = $btn.data('reaction');

    const $item    = $btn.closest('.activity-item');
    const id       = $item.data('id');

    const $meta = $item.find(
        `.reaction-meta[data-reaction="${reaction}"]`
    );

    let $countEl = $meta.find('.count');
    const count  = parseInt($countEl.text(), 10) || 0;

    // Optimistic UI
    $countEl.text(count + 1);
    $item.find('.reaction-trigger').text($btn.text());
    $item.find('.reaction-box').removeClass('open');

    $.post('api/modules/activity/react', {
        activity_id: id,
        reaction: reaction
    });
});
console.log('here');
// ------------------------------------------------------------
// Comments (inline)
// ------------------------------------------------------------

$(document).on('click', '.act-comment', function (e) {
    e.preventDefault();

    const activityId = $(this)
        .closest('.activity-item')
        .data('id');

    mPGs.klassView(
        'Activity',
        'comments',
        activityId,
        {
            size: 'lg',
            state: {
                focus: 'composer'
            }
        }
    );
    

});

$(document).on('click', '.send-comment', function () {
    const $item = $(this).closest('.activity-item');
    const body = $item.find('.comment-body').val();
    const id = $item.data('id');

    if (!body.trim()) return;

    $.post('api/modules/activity/comment', {
        activity_id: id,
        body: body
    }).done(() => {
        $item.find('.comment-body').remove();
        $(this).remove();
    });
});

$(document).on('click', '.composer-placeholder', function () {
    return openPostPopup();
});


$(document).on('click', '.reply-comment', function (e) {
    e.preventDefault();

    const activityId = $(this)
        .closest('.comment-item')
        .data('id');

    mPGs.klassView(
        'Activity',
        'replies',
        activityId,
        {
            size: 'lg',
            state: {
                focus: 'composer'
            }
        }
    );
    

});