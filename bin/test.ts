import { configure, processCLIArgs, run } from '@japa/runner'
import { assert } from '@japa/assert'
import { expectTypeOf } from '@japa/expect-type'

processCLIArgs(process.argv.splice(2))
configure({
  files: ['tests/**/*.spec.ts'],
  plugins: [assert(), expectTypeOf()],
  reporters: {
    activated: ['sample'],
    list: [
      {
        name: 'sample',
        async handler(runner, emitter) {
          emitter.on('runner:end', () => {
            console.log(runner.getSummary())
          })
        },
      },
    ],
  },
})

void run()
