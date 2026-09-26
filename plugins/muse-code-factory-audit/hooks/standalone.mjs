// Entry point for the user-settings fallback installer, which invokes one file
// for every configured hook event instead of using Muse's native plugin loader.
import { runHook } from './audit.mjs';

runHook();
