// src/Core/Modules/Grids/Assets/js/index.js

import { initGrids } from './grids.js';
import { GridActions } from './actions.js';
import './events.js';

const Grids = {
    init: initGrids,
    actions: GridActions
};

// namespace-safe global
window.Bora = window.Bora || {};
window.Bora.Grids = Grids;

export default Grids;
