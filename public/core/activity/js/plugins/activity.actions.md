const routeRegistry = await scope.getService('route.registry');

// Ref
// routeRegistry.register('activity.comments', ({ id, tab }) => ({
//     size: 'md',
//     tabs: [
//         {
//             id: 'replies',
//             label: 'Comments',
//             url: `api/modules/activity/timeline/comments/${id}`
//         }
//     ],
//     activeTab: tab || 'replies'
// }));