import type {Policy} from './engine/types';
// Configure locally before building. No network-based policy retrieval.
export const CORPORATE_POLICY:Policy={
 internalDomains:[],
 protectedNames:[]
};
