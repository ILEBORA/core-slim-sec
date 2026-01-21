// grids.js
import { GridsConfig } from './config.js';

export function initGrids(options = {}) {
    GridsConfig.init(options);
    console.log('Grids initialized');
}