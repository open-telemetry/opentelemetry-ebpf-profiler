using System.Reflection.Emit;

internal sealed class DynamicMethodOwner;

internal static class Program
{
	private const int DynamicMethodCount = 3;

	public static void Main()
	{
		using var entered = new CountdownEvent(DynamicMethodCount);
		var methods = new[]
		{
			CreateRunner(new DynamicMethod(
				"AnonymousDynamicMethod",
				typeof(void),
				[typeof(CountdownEvent), typeof(TextWriter)])),
			CreateRunner(new DynamicMethod(
				"ModuleDynamicMethod",
				typeof(void),
				[typeof(CountdownEvent), typeof(TextWriter)],
				typeof(Program).Module)),
			CreateRunner(new DynamicMethod(
				"OwnerDynamicMethod",
				typeof(void),
				[typeof(CountdownEvent), typeof(TextWriter)],
				typeof(DynamicMethodOwner))),
		};

		foreach (var method in methods)
		{
			new Thread(() =>
			{
				using var stream = new FileStream(
					"/dev/null",
					FileMode.Open,
					FileAccess.Write,
					FileShare.ReadWrite);
				using var writer = new StreamWriter(stream)
				{
					AutoFlush = true,
				};
				method(entered, writer);
			}).Start();
		}

		entered.Wait();
		Console.WriteLine("All dynamic methods are running");
		Thread.Sleep(Timeout.Infinite);
	}

	private static Action<CountdownEvent, TextWriter> CreateRunner(DynamicMethod method)
	{
		var signalMethod = typeof(CountdownEvent).GetMethod(
			nameof(CountdownEvent.Signal),
			Type.EmptyTypes) ?? throw new InvalidOperationException("CountdownEvent.Signal not found");
		var writeLineMethod = typeof(TextWriter).GetMethod(
			nameof(TextWriter.WriteLine),
			[typeof(string)]) ?? throw new InvalidOperationException("TextWriter.WriteLine not found");

		var il = method.GetILGenerator();
		il.Emit(OpCodes.Ldarg_0);
		il.Emit(OpCodes.Callvirt, signalMethod);
		il.Emit(OpCodes.Pop);

		var loop = il.DefineLabel();
		il.MarkLabel(loop);
		il.Emit(OpCodes.Ldarg_1);
		il.Emit(OpCodes.Ldstr, method.Name);
		il.Emit(OpCodes.Callvirt, writeLineMethod);
		il.Emit(OpCodes.Br_S, loop);

		return (Action<CountdownEvent, TextWriter>)method.CreateDelegate(
			typeof(Action<CountdownEvent, TextWriter>));
	}
}
