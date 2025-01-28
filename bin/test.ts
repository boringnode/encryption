import { configure, processCLIArgs, run } from '@japa/runner'
import { spec } from '@japa/runner/reporters'
import { assert } from '@japa/assert'
import { expectTypeOf } from '@japa/expect-type'

processCLIArgs(process.argv.splice(2))
configure({
  files: ['tests/sample.spec.ts'],
  plugins: [assert(), expectTypeOf()],
  reporters: {
    activated: [spec.name],
    list: [spec()],
  },
})

void run()
