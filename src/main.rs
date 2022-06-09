// starting with "compute" example from metal-rs

use metal::*;
use objc::rc::autoreleasepool;
use std::mem;

// TODO: build this string using macros?
static LIBRARY_SRC: &str = "#include <metal_stdlib>

using namespace metal;

struct SumInput {
    device uint *data;
    volatile device atomic_uint *sum;
};

kernel void sum(device SumInput& input [[ buffer(0) ]],
                uint gid [[ thread_position_in_grid ]])
{
    atomic_fetch_add_explicit(input.sum, input.data[gid], memory_order_relaxed);
}";

fn main() {
    autoreleasepool(|| {
        let device = Device::system_default().expect("no device found");
        let command_queue = device.new_command_queue();

        let data = [
            1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30,
        ];

        let buffer = device.new_buffer_with_data(
            unsafe { mem::transmute(data.as_ptr()) },
            (data.len() * mem::size_of::<u32>()) as u64,
            MTLResourceOptions::CPUCacheModeDefaultCache,
        );

        let sum = {
            let data = [0u32];
            device.new_buffer_with_data(
                unsafe { mem::transmute(data.as_ptr()) },
                (data.len() * mem::size_of::<u32>()) as u64,
                MTLResourceOptions::CPUCacheModeDefaultCache,
            )
        };

        let command_buffer = command_queue.new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();

        let library = device
            .new_library_with_source(LIBRARY_SRC, &CompileOptions::new())
            .unwrap();
        let kernel = library.get_function("sum", None).unwrap();

        let argument_encoder = kernel.new_argument_encoder(0);
        let arg_buffer = device.new_buffer(
            argument_encoder.encoded_length(),
            MTLResourceOptions::empty(),
        );
        argument_encoder.set_argument_buffer(&arg_buffer, 0);
        argument_encoder.set_buffer(0, &buffer, 0);
        argument_encoder.set_buffer(1, &sum, 0);

        let pipeline_state_descriptor = ComputePipelineDescriptor::new();
        pipeline_state_descriptor.set_compute_function(Some(&kernel));

        let pipeline_state = device
            .new_compute_pipeline_state_with_function(
                pipeline_state_descriptor.compute_function().unwrap(),
            )
            .unwrap();

        encoder.set_compute_pipeline_state(&pipeline_state);
        encoder.set_buffer(0, Some(&arg_buffer), 0);

        encoder.use_resource(&buffer, MTLResourceUsage::Read);
        encoder.use_resource(&sum, MTLResourceUsage::Write);

        let width = 16;

        let thread_group_count = MTLSize {
            width,
            height: 1,
            depth: 1,
        };

        let thread_group_size = MTLSize {
            width: (data.len() as u64 + width) / width,
            height: 1,
            depth: 1,
        };

        encoder.dispatch_thread_groups(thread_group_count, thread_group_size);
        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        let ptr = sum.contents() as *mut u32;
        unsafe {
            println!("{}", *ptr);
            assert_eq!(465, *ptr);
        }
    });
}
