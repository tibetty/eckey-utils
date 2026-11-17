/**
 * Vitest's failure formatter uses `Map.groupBy`, which arrived in Node 21. On
 * Node 20 any failing assertion is reported as `TypeError: Map.groupBy is not
 * a function` instead of the message, so add the missing method when the
 * runtime is too old.
 */
interface MapWithGroupBy {
    groupBy?: (
        items: Iterable<unknown>,
        key: (item: unknown, index: number) => unknown
    ) => Map<unknown, unknown[]>;
}

const mapWithGroupBy = Map as unknown as MapWithGroupBy;

if (typeof mapWithGroupBy.groupBy !== 'function') {
    mapWithGroupBy.groupBy = (items, key) => {
        const groups = new Map<unknown, unknown[]>();
        let index = 0;
        for (const item of items) {
            const groupKey = key(item, index++);
            const group = groups.get(groupKey) ?? [];
            group.push(item);
            groups.set(groupKey, group);
        }
        return groups;
    };
}
