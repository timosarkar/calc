# tryna write a simple tensor in py and rewrite in zig afterwards
# shape is how many sub-arrays are nested (2)
# fill_value is the value set in the arrays
def generate_tensor(shape, fill_value):
    if len(shape) == 0:
        return fill_value

    size = shape[0]
    dimensions = shape[1:]
    tensor = []
    for i in range(size):
        tensor.append(generate_tensor(dimensions, fill_value))
    return tensor

a=generate_tensor([2,3], 0.0)
print(a) # might add class Tensor.__repr__

"""
[
    [0.0, 0.0, 0.0],
    [0.0, 0.0, 0.0]
]
"""
