// Read-only aggregate statistics; no identifiers or individual records are printed.
print('Label distribution in standard_records:');
printjson(db.standard_records.aggregate([
  {$group: {_id: {label: '$Label', type: {$type: '$Label'}}, count: {$sum: 1}}},
  {$sort: {count: -1}}
], {allowDiskUse: true}).toArray());
print('Per-class feature statistics from up to 20000 sampled standard records:');
printjson(db.standard_records.aggregate([
  {$sample: {size: 20000}},
  {$project: {label: '$Label', fields: {$objectToArray: '$$ROOT'}}},
  {$unwind: '$fields'},
  {$match: {'fields.k': {$nin: ['_id', 'original_id', 'Label', 'block_index']}}},
  {$project: {label: 1, field: '$fields.k', numeric: {$isNumber: '$fields.v'},
    value: {$cond: [{$isNumber: '$fields.v'}, '$fields.v', null]}}},
  {$group: {_id: {field: '$field', label: '$label'}, samples: {$sum: 1},
    numeric: {$sum: {$cond: ['$numeric', 1, 0]}},
    min: {$min: '$value'}, max: {$max: '$value'}, stddev: {$stdDevPop: '$value'},
    zeros: {$sum: {$cond: [{$and: ['$numeric', {$eq: ['$value', 0]}]}, 1, 0]}},
    ones: {$sum: {$cond: [{$and: ['$numeric', {$eq: ['$value', 1]}]}, 1, 0]}},
    outside_unit_range: {$sum: {$cond: [{$and: ['$numeric', {$or: [{$lt: ['$value', 0]}, {$gt: ['$value', 1]}]}]}, 1, 0]}}
  }},
  {$sort: {'_id.field': 1, '_id.label': 1}}
], {allowDiskUse: true}).toArray());
