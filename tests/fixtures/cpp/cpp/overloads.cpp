// Fixture for T-06-02: an overload set shares a name and nothing else.
int convert(int value)
{
    return value;
}

int convert(double value)
{
    return static_cast<int>(value);
}

int use_both(int value)
{
    return convert(value) + convert(static_cast<double>(value));
}
